// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * Copyright (c) 2025 Tom Herbert
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* XDP2 main parsing logic */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>

#include "xdp2/parser.h"
#include "siphash/siphash.h"

/* Lookup a type in a node table*/
static const struct xdp2_parse_node *lookup_node(int type,
				    const struct xdp2_proto_table *table)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (type == table->entries[i].value)
			return table->entries[i].node;

	return NULL;
}

/* Lookup a type in a node TLV table */
static const struct xdp2_parse_tlv_node *lookup_tlv_node(int type,
				const struct xdp2_proto_tlvs_table *table)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (type == table->entries[i].type)
			return table->entries[i].node;

	return NULL;
}

/* Lookup up a protocol for the table associated with a parse node */
const struct xdp2_parse_tlv_node *xdp2_parse_lookup_tlv(
		const struct xdp2_parse_tlvs_node *node,
		unsigned int type)
{
	return lookup_tlv_node(type, node->tlv_proto_table);
}

/* Lookup a flag-fields index in a protocol node flag-fields table */
static const struct xdp2_parse_flag_field_node *lookup_flag_field_node(int idx,
				const struct xdp2_proto_flag_fields_table
								*table)
{
	int i;

	for (i = 0; i < table->num_ents; i++)
		if (idx == table->entries[i].index)
			return table->entries[i].node;

	return NULL;
}

static int xdp2_parse_tlvs(const struct xdp2_parse_node *parse_node,
			   const void *hdr, size_t hlen, size_t offset,
			   void *frame, struct xdp2_ctrl_data *ctrl,
			   unsigned int flags);

static int xdp2_parse_one_tlv(
		const struct xdp2_parse_tlvs_node *parse_tlvs_node,
		const struct xdp2_parse_tlv_node *parse_tlv_node,
		const void *hdr, void *frame, int type, size_t tlv_len,
		size_t offset, struct xdp2_ctrl_data *ctrl,
		unsigned int flags)
{
	const struct xdp2_proto_tlv_def *proto_tlv_def =
					parse_tlv_node->proto_tlv_def;
	const struct xdp2_parse_tlv_node *parse_tlv_node_next;
	const struct xdp2_parse_tlv_node_ops *ops;
	int ret;

parse_again:

	if (flags & XDP2_F_DEBUG)
		printf("XDP2 parsing TLV %s\n", parse_tlv_node->name);

	if (proto_tlv_def && (tlv_len < proto_tlv_def->min_len)) {
		/* Treat check length error as an unrecognized TLV */
		parse_tlv_node = parse_tlvs_node->tlv_wildcard_node;
		if (parse_tlv_node)
			goto parse_again;
		else
			return parse_tlvs_node->unknown_tlv_type_ret;
	}

	ops = &parse_tlv_node->tlv_ops;

	/* Set up header length and header offset as arguments */
	ctrl->hdr.hdr_len = tlv_len;
	ctrl->hdr.hdr_offset = offset;

	if (ops->extract_metadata)
		ops->extract_metadata(hdr, frame, *ctrl);

	if (ops->handler) {
		ret = ops->handler(hdr, frame, *ctrl);
		if (ret != XDP2_OKAY)
			return ret;
	}

	if (parse_tlv_node->nested_node) {
		size_t nested_offset = 0;

		if (proto_tlv_def->ops.nested_offset)
			nested_offset =
				proto_tlv_def->ops.nested_offset(hdr, tlv_len);
		ctrl->hdr.tlv_levels++;
		ret = xdp2_parse_tlvs(parse_tlv_node->nested_node,
			    hdr + nested_offset, tlv_len - nested_offset,
			    offset + nested_offset, frame, ctrl, flags);
		ctrl->hdr.tlv_levels--;

		if (ret != XDP2_OKAY)
			return ret;
	}

	if (!parse_tlv_node->overlay_table)
		return XDP2_OKAY;

	/* We have an TLV overlay  node */

	if (proto_tlv_def->ops.overlay_type)
		type = proto_tlv_def->ops.overlay_type(hdr);
	else
		type = tlv_len;

	/* Get TLV node */
	parse_tlv_node_next = lookup_tlv_node(type,
					parse_tlv_node->overlay_table);
	if (parse_tlv_node_next) {
		parse_tlv_node = parse_tlv_node_next;
		goto parse_again;
	}

	/* Unknown TLV overlay node */
	parse_tlv_node_next = parse_tlv_node->overlay_wildcard_node;
	if (parse_tlv_node_next) {
		parse_tlv_node = parse_tlv_node_next;
		goto parse_again;
	}

	return parse_tlv_node->unknown_overlay_ret;
}

static int xdp2_parse_tlvs(const struct xdp2_parse_node *parse_node,
			   const void *hdr, size_t hlen,
			   size_t offset, void *frame,
			   struct xdp2_ctrl_data *ctrl,
			   unsigned int flags)
{
	const struct xdp2_parse_tlvs_node *parse_tlvs_node;
	const struct xdp2_proto_tlvs_def *proto_tlvs_def;
	const struct xdp2_parse_tlv_node *parse_tlv_node;
	const __u8 *cp = hdr;
	ssize_t tlv_len;
	int type, ret;
	size_t off;

	parse_tlvs_node = (struct xdp2_parse_tlvs_node *)parse_node;
	proto_tlvs_def = (struct xdp2_proto_tlvs_def *)
						parse_node->proto_def;

	/* Assume hlen marks end of TLVs */
	off = proto_tlvs_def->ops.start_offset(hdr);

	/* We assume start offset is less than or equal to minimal length */
	hlen -= off;

	cp += off;
	offset += off;

	while (hlen > 0) {
		if (proto_tlvs_def->pad1_enable &&
		   *cp == proto_tlvs_def->pad1_val) {
			/* One byte padding, just advance */
			cp++;
			offset++;
			hlen--;
			continue;
		}

		if (proto_tlvs_def->eol_enable &&
		    *cp == proto_tlvs_def->eol_val) {
			cp++;
			offset++;
			hlen--;

			/* Hit EOL, we're done */
			break;
		}

		if (hlen < proto_tlvs_def->min_len) {
			/* Length error */
			return XDP2_STOP_TLV_LENGTH;
		}

		/* If the len function is not set this degenerates to an
		 * array of fixed sized values (which maybe be useful in
		 * itself now that I think about it)
		 */
		if (proto_tlvs_def->ops.len ||
		    proto_tlvs_def->ops.len_maxlen) {
			tlv_len = proto_tlvs_def->ops.len_maxlen ?
				proto_tlvs_def->ops.len_maxlen(cp, hlen) :
				proto_tlvs_def->ops.len(cp);
			if (!tlv_len || hlen < tlv_len)
				return XDP2_STOP_TLV_LENGTH;

			if (tlv_len < proto_tlvs_def->min_len)
				return tlv_len < 0 ? tlv_len :
						XDP2_STOP_TLV_LENGTH;
		} else {
			tlv_len = proto_tlvs_def->min_len;
		}

		type = proto_tlvs_def->ops.type(cp);

		/* Get TLV node */

		parse_tlv_node = parse_tlvs_node->tlv_proto_table ?
			lookup_tlv_node(type,
					parse_tlvs_node->tlv_proto_table) :
			NULL;

		if (parse_tlv_node) {
parse_one_tlv:
			ret = xdp2_parse_one_tlv(parse_tlvs_node,
						  parse_tlv_node, cp, frame,
						  type, tlv_len, offset,
						  ctrl, flags);
			if (ret != XDP2_OKAY)
				return ret;
		} else {
			/* Unknown TLV */
			parse_tlv_node = parse_tlvs_node->tlv_wildcard_node;
			if (parse_tlv_node) {
				/* If a wilcard node is present parse that
				 * node as an overlay to this one. The
				 * wild card node can perform error processing
				 */
				goto parse_one_tlv;
			} else {
				/* Return default error code. Returning
				 * XDP2_OKAY means skip
				 */
				if (parse_tlvs_node->unknown_tlv_type_ret !=
				    XDP2_OKAY)
					return
					  parse_tlvs_node->unknown_tlv_type_ret;
			}
		}

		/* Move over current header */
		cp += tlv_len;
		offset += tlv_len;
		hlen -= tlv_len;
	}

	return XDP2_OKAY;
}

static int xdp2_parse_flag_fields(const struct xdp2_parse_node *parse_node,
				   const void *hdr, size_t hlen,
				   size_t offset, void *frame,
				   struct xdp2_ctrl_data *ctrl,
				   unsigned int pflags)
{
	const struct xdp2_parse_flag_fields_node *parse_flag_fields_node;
	const struct xdp2_proto_flag_fields_def *proto_flag_fields_def;
	const struct xdp2_parse_flag_field_node *parse_flag_field_node;
	const struct xdp2_flag_fields *flag_fields;
	size_t ioff;
	ssize_t off;
	__u32 flags;
	int i;

	parse_flag_fields_node =
			(struct xdp2_parse_flag_fields_node *)parse_node;
	proto_flag_fields_def =
			(struct xdp2_proto_flag_fields_def *)
						parse_node->proto_def;
	flag_fields = proto_flag_fields_def->flag_fields;

	flags = proto_flag_fields_def->ops.get_flags(hdr);

	/* Position at start of field data */
	ioff = proto_flag_fields_def->ops.start_fields_offset(hdr);
	hdr += ioff;
	offset += ioff;

	for (i = 0; i < flag_fields->num_idx; i++) {
		off = xdp2_flag_fields_offset(i, flags, flag_fields);
		if (off < 0)
			continue;

		/* Flag field is present, try to find in the parse node
		 * table based on index in proto flag-fields
		 */
		parse_flag_field_node = lookup_flag_field_node(i,
			parse_flag_fields_node->flag_fields_proto_table);
		if (parse_flag_field_node) {
			const struct xdp2_parse_flag_field_node_ops
				*ops = &parse_flag_field_node->ops;
			const __u8 *cp = hdr + off;

			if (pflags & XDP2_F_DEBUG)
				printf("XDP2 parsing flag-field %s\n",
				      parse_flag_field_node->name);

			/* Set up header length and header offset as
			 * arguments
			 */
			ctrl->hdr.hdr_len = flag_fields->fields[i].size;
			ctrl->hdr.hdr_offset = offset + off;

			if (ops->extract_metadata)
				ops->extract_metadata(cp, frame, *ctrl);

			if (ops->handler)
				ops->handler(cp, frame, *ctrl);
		}
	}

	return XDP2_OKAY;
}

/* Parse a packet
 *
 * Arguments:
 *   - parser: Parser being invoked
 *   - node: start root node (may be different than parser->root_node)
 *   - hdr: pointer to start of packet
 *   - len: length of packet
 *   - metadata: metadata structure
 *   - start_node: first node (typically node_ether)
 *   - flags: allowed parameterized parsing
 */
int __xdp2_parse(const struct xdp2_parser *parser,
		 const struct xdp2_packet_data *pdata, void *metadata,
		 unsigned int flags)
{
	ssize_t hlen, len = pdata->hdrs ? pdata->hdrs_len : pdata->pkt_len;
	const struct xdp2_parse_node *parse_node = parser->root_node;
	void *frame = metadata + parser->config.metameta_size;
	const struct xdp2_parse_node *next_parse_node;
	void *hdr = pdata->hdrs ? : pdata->packet;
	const struct xdp2_proto_def *proto_def;
	struct xdp2_ctrl_data ctrl;
	unsigned int frame_num = 0;
	size_t offset = 0;
	int type, ret;

	/* Main parsing loop. The loop normal teminates when we encounter a
	 * leaf node, an error condition, hitting limit on layers of
	 * encapsulation, protocol condition to stop (i.e. flags that
	 * indicate to stop at flow label or hitting fragment), or
	 * unknown protocol result in table lookup for next node.
	 */

	__XDP2_PARSE_INIT_CTRL(parser, ctrl);

	ctrl.pkt = *pdata;
	ctrl.var.metadata = metadata;

	do {
		proto_def = parse_node->proto_def;

		if (flags & XDP2_F_DEBUG)
			printf("XDP2 parsing %s, remaining length %lu\n",
			       proto_def->name, len);

		hlen = proto_def->min_len;

		ctrl.var.last_node = parse_node;

		/* Protocol definition length checks */

		if (len < hlen) {
			ret = XDP2_STOP_LENGTH;
			goto out;
		}

		if (proto_def->ops.len || proto_def->ops.len_maxlen) {
			hlen = proto_def->ops.len_maxlen ?
				proto_def->ops.len_maxlen(hdr, len) :
				proto_def->ops.len(hdr);
			if (len < hlen) {
				ret = XDP2_STOP_LENGTH;
				goto out;
			}

			if (hlen < proto_def->min_len) {
				ret = hlen < 0 ? hlen : XDP2_STOP_LENGTH;
				goto out;
			}
		} else {
			hlen = proto_def->min_len;
		}

		/* Callback processing order
		 *    1) Extract Metadata
		 *    2) Call handler
		 *    3) Process TLVs or flag fields
		 *	3.a) Extract metadata from each object
		 *	3.b) Call handler for each object
		 *    4) Call post handler
		 */

		/* Set up header length and header offset as arguments */
		ctrl.hdr.hdr_len = hlen;
		ctrl.hdr.hdr_offset = offset;

		/* Extract metadata */
		if (parse_node->ops.extract_metadata)
			parse_node->ops.extract_metadata(hdr, frame, ctrl);

		/* Call handler */
		if (parse_node->ops.handler)
			parse_node->ops.handler(hdr, frame, ctrl);

		switch (parse_node->node_type) {
		case XDP2_NODE_TYPE_PLAIN:
		default:
			break;
		case XDP2_NODE_TYPE_TLVS:
			/* Process TLV nodes */
			if (parse_node->proto_def->node_type ==
			    XDP2_NODE_TYPE_TLVS) {
				/* Need error in case parse_node is TLVs type
				 * but proto_def is not TLVs type
				 */
				ret = xdp2_parse_tlvs(parse_node, hdr, hlen,
						      offset, frame, &ctrl,
						      flags);
				if (ret != XDP2_OKAY)
					goto out;
			}
			break;
		case XDP2_NODE_TYPE_FLAG_FIELDS:
			/* Process flag-fields */
			if (parse_node->proto_def->node_type ==
						XDP2_NODE_TYPE_FLAG_FIELDS) {
				/* Need error in case parse_node is flag-fields
				 * type but proto_def is not flag-fields type
				 */
				ret = xdp2_parse_flag_fields(parse_node, hdr,
							     hlen, offset,
							     frame, &ctrl,
							     flags);
				if (ret != XDP2_OKAY)
					goto out;
			}
			break;
		}

		/* Call handler */
		if (parse_node->ops.post_handler)
			parse_node->ops.post_handler(hdr, frame, ctrl);

		/* Proceed to next protocol layer */

		if (!parse_node->proto_table && !parse_node->wildcard_node) {
			/* Leaf parse node */

			ret = XDP2_STOP_OKAY;
			goto out;
		}

		if (proto_def->encap) {
			if (parser->config.atencap_node) {
				ret = __xdp2_parse_run_exit_node(parser,
					parser->config.atencap_node,
					metadata, frame, &ctrl, flags);
				if (ret != XDP2_OKAY)
					goto out;
			}

			/* New encapsulation leyer. Check against
			 * number of encap layers allowed and also
			 * if we need a new metadata frame.
			 */
			if (++ctrl.var.encaps > parser->config.max_encaps) {
				ret = XDP2_STOP_ENCAP_DEPTH;
				goto out;
			}

			if (parser->config.max_frames > frame_num) {
				frame += parser->config.frame_size;
				frame_num++;
			}
		}

		if (parse_node->proto_table &&
		    (proto_def->ops.next_proto ||
		     proto_def->ops.next_proto_keyin)) {
			/* Lookup next proto */

			type = proto_def->ops.next_proto_keyin ?
				proto_def->ops.next_proto_keyin(hdr,
					ctrl.var.keys[parse_node->key_sel]) :
				proto_def->ops.next_proto(hdr);
			if (type < 0) {
				ret = type;
				goto out;
			}

			/* Get next node */
			next_parse_node = lookup_node(type,
						parse_node->proto_table);

			if (next_parse_node)
				goto found_next;
		}

		/* Try wildcard node. Either table lookup failed to find a node
		 * or there is only a wildcard
		 */
		if (parse_node->wildcard_node) {
			/* Perform default processing in a wildcard node */

			next_parse_node = parse_node->wildcard_node;
		} else {
			/* Return default code. Parsing will stop
			 * with the inidicated code
			 */

			ret = parse_node->unknown_ret;
			goto out;
		}

found_next:
		/* Found next parse node, set up to process */

		if (!proto_def->overlay) {
			/* Move over current header */
			offset += hlen;
			hdr += hlen;
			len -= hlen;
		}

		if (!len && (parse_node->flags &
			     XDP2_PARSE_NODE_F_ZERO_LEN_OK)) {
			ret = XDP2_STOP_OKAY;
			goto out;
		}

		parse_node = next_parse_node;

	} while (1);

out:
	parse_node = XDP2_CODE_IS_OKAY(ret) ?
			parser->config.okay_node : parser->config.fail_node;

	ctrl.var.ret_code = ret;

	if (parse_node)
		__xdp2_parse_run_exit_node(parser, parse_node, metadata, frame,
					   &ctrl, flags);

	return ret;
}

siphash_key_t __xdp2_hash_key;
void xdp2_hash_secret_init(siphash_key_t *init_key)
{
	if (init_key) {
		__xdp2_hash_key = *init_key;
	} else {
		__u8 *bytes = (__u8 *)&__xdp2_hash_key;
		int i;

		for (i = 0; i < sizeof(__xdp2_hash_key); i++)
			bytes[i] = rand();
	}
}

void xdp2_print_hash_input(const void *start, size_t len)
{
	const __u8 *data = start;
	int i;

	printf("Hash input (size %lu): ", len);
	for (i = 0; i < len; i++)
		printf("%02x ", data[i]);
	printf("\n");
}
