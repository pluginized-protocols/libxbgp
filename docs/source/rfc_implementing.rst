================================================
Implementing RFCs from minimal BGP with plugins
================================================

This section explains how to implement RFCs that add new extensions with eBPF plugins
to a minimal BGP implementation as defined on rfc4271.

Insertion Point
===============
The BGP implementation must propose those insertion points, so that, plugins can be
hooked to them.

`BGP_ENCODE_ATTR`
    This insertion point handles the encoding of all attributes related to a given BGP
    route. Arguments passed through the plugin are the current attribute to be encoded and
    the buffer dedicated to the attribute in the BGP UPDATE message. The latter argument is
    hidden from the plugin since multiple implementations can use different representation.
    Accessing to this buffer must be done via helper functions.

`BGP_DECODE_ATTR`
    This insertion point will be used for plugin that want to decode a given attribute.
    Arguments passed to plugins are the following:

    - The buffer containing the attribute content in network byte order, as hidden argument
    - The internal data structure to store the decoded attribute, as hidden argument
    - The current list of attributes, as hidden argument
    - The decoded attribute CODE, as uint8_t
    - The decoded flags related to the processed attribute
    - The decoded length of the attribute

    The insertion point is also valid to decode Mutliprotocols (MP) Extensions. In this
    case, when the prefix is decoded, it must be announced to the host implementation
    with the helper function `announce_nlri()`.

`BGP_DECODE_REACH_NLRI`
    This insertion point decode a buffer containing the all NRLI encoded to a BGP UPDATE
    message. Arguments are then :

    - The peer information
    - The buffer in network format with the NLRIs.
    - The AFI
    - The SAFI
    - The buffer length

    To announce a prefix to the host implementation, the helper function
    `announce_nlri` must be used. Otherwise, BGP won't include this path to
    the BGP decision process.

    This insertion point only decode the NRLI passed through the last part of the update
    message (and therefore does not support Multiprotocols extensions).

`BGP_DECODE_WITHDRAW_NLRI`
    This insertion point is used to decode prefixes that needs to be withdrawn.
    The following arguments must be passed through the plugin :

    - The peer information
    - The AFI
    - The SAFI
    - The buffer containing the unfeasible routes
    - The buffer length

`BGP_INBOUND_PRE_FILTER`
    This insertion point is used to whether accept or not the route into the local router.
    Plugins are executed just before user defined inbound filters.

    Arguments involved to this insertion point:

    - The current route prefix
    - The peer information
    - List of route attributes

`BGP_INBOUND_FILTER`
    The insertion point executes user defined filters when the route is received
    on the inbound side of the router.

    Arguments are the same as ``BGP_INBOUND_PRE_FILTER``

`BGP_OUTBOUND_PRE_FILTER`
    This insertion point is used to check whether or not the route must be announced to
    the remote peer. As ``BGP_INBOUND_PRE_FILTER``, plugins attached to it are executed
    just before user defined outbound filters.

    Arguments needed for this insertion point are:

    - The current route prefix
    - The peer information
    - List of route attributes

`BGP_OUTBOUND_FILTER`
    Executes the user defined filters when the route is received on the outbound side of the
    router.

    Arguments are the same as ``BGP_OUTBOUND_PRE_FILTER``

`BGP_DECISION_PROCESS`
    Insertion point to reimplement the BGP decision process.
    TODO, dispatch function to invoke either a new
    The decision process insertion point takes multiple arguments:

    - The old route
    - The new received route

    The two received routes both contain :

    - The peer from which the router has received it
    - The current prefix to process
    - The attribute list related to the path

`BGP_RECEIVED_MESSAGE`
    Used to decode a given type of BGP message. When the BGP header been parsed (i.e. the
    marker, the length and the type) the whole buffer containing the acutal message
    is returned to the plugin. It can then parse as convenience a new BGP message such as
    route refresh.

    Argument to be given to the plugin in charge of decoding an incoming message are :

    - The peer information
    - The type code for the BGP Message
    - The buffer encoded in network format

    This insertion point is essentially used to decode new BGP messages (other than
    OPEN, UPDATE, KEEPALIVE and NOTIFICATION). However, the host implementation could
    decide to completely override the code of the actual implementation. However, we
    do not recommend to put this kind of insertion point to decode a whole BGP
    UPDATE. We provide other insertion points that handle parts of a BGP update.

`BGP_ENCODE_MESSAGE`
    Used to encode a whole new BGP message (preferably other than OPEN, KEEPALIVE,
    UPDATE and NOTIFICATION) in network format. The argument given to this insertion
    point are:

    - The peer information
    - The kind of BGP update to encode
    - [AS HIDDEN] The host buffer that will be transmitted to the peer

`BGP_OPEN_DECODE_OPT_PARAM`
    This insertion point decode one specific optional parameter carried into the BGP OPEN
    message. The arguments are:

    - The peer information
    - The optional parameter type
    - The optional parameter length
    - A buffer containing the parameter in network format

`BGP_OPEN_ENCODE_OPT_PARAM`
    This insertion point is used to add an optional parameter to the open message.
    One pluglet correspond to one optional parameter. Its arguments are:

    - The peer information
    - [AS HIDDEN] The buffer that will be written when `write_to_buffer` is called.

Helper Function
===============
Helper function are mostly designed to retrieve (resp. store) data from (resp. to) the
hist implementation

`int add_attr(uint code, uint flags, uint16_t length, uint8_t *decoded_attr)`
    Adds the attribute specified onto its arguments to the route the plugin is currently
    processing. The route is not specified since the plugin calling this function assumes
    it only processes one route at once.

`struct path_attribute *get_attr()`
    Gets the current attribute the plugins is processing. To use this function,
    one of the plugin's arguments must be the attribute. If multiple attribute are
    given to the plugin, check ``get_attr_by_code``

`struct path_attribute *get_attr_by_code(uint8_t code)`
    If the plugin are involved to a

`int write_to_buffer(uint8_t *buf, size_t len)`
    The function copies the content of ``buf`` up to len bytes into the internal buffer
    of the host implementation passed as hidden arguments to the plugin. Only one internal
    buffer must be provided to the hidden argument of the plugin.

`void *bpf_get_args(bpf_full_args_t *args, int pos_id)`
    Built-in function that retrieve the argument from the host implementation.
    The function copies into the plugin memory according to the data contained
    into the structure defining the arguments of the insertion point.

    Let us take this small example :

    .. code-block :: c

         bpf_args_t args[] = {
                    [0] = {.arg = &type, .len = sizeof(uint8_t), .kind= kind_primitive, .type = UNSIGNED_INT},
                    [1] = {.arg = &flag, .len = sizeof(uint8_t), .kind = kind_primitive, .type = UNSIGNED_INT},
                    [2] = {.arg = stream_pnt(BGP_INPUT(peer)), .len = length, .kind=kind_ptr, .type = BUFFER_ARRAY},
                    [3] = {.arg = &attr_args.length, .len = sizeof(uint16_t), .kind=kind_primitive, .type = UNSIGNED_INT},
                    [4] = {.arg = attr->ubpf_mempool, .len=sizeof(mem_pool *), .kind=kind_hidden, .type=MEMPOOL},
                    [5] = {.arg = attr, .len=sizeof(attr), .kind= kind_hidden, .type=ATTRIBUTE},
            };

    When the plugin wants to access to the buffer located at argument index 2, it calls
    ``bpf_get_args``. Internally, the helper function looks if it has the right to retrieve
    the argument. It will then copies the content of the pointer ``arg`` by ``len`` bytes
    to an allowed plugin memory area.

`struct ubpf_peer_info get_peer_info()`
    Returns a structure containing the information related to a given peer.
    Currently the structure is defined as such:

    .. code-block:: c

        struct ubpf_peer_info {
            uint32_t as;
            uint32_t router_id;
            uint32_t capability;
            uint8_t peer_type;

            struct {
                uint8_t af;
                struct sockaddr sa;
            } addr;

            % extra information related to the peer
            mempool_t *mempool;
        };

`uint32_t get_local_router_id()`
    It will find and return the local router ID for the given session. Be sure to have
    an hidden argument which contains the local router ID.

`uint32_t get_cluster_id()`
    Retrieves the cluster ID on which this BGP router belongs to. 0 is returned if no
    cluster ID has been set for this BGP instance.

`int add_route_rib(struct ubpf_path *rte)` TODO CHECK ARGUMENTS
    Adds a new route into the BGP RIB of the host implementation.

sthg to walk to the RIB/Adj-RIB-Out

`int parsed_nrli(struct ubpf_prefix *pfx)`
    Used to inform the protocol that a prefix has been parsed.
    For each update message, the host implementation keeps a list (or a user defined
    date structure) that will be filled by this helper function. When all NRLI from
    an update message has been decoded, the host implementation will use this list
    to continue its execution and then continue the BGP UPDATE processing.
    To be able to use this function, the base implementation must be a little
    bit altered to allow using the ``struct ubpf_prefix`` to represent a prefix into
    memory. Hence, every function using an internal representation of the prefix must be
    modified to use this custom defined function.

RFC4456
=======

This documents describe how to define route reflectors and confederations.

Route Reflectors introduce new route attributes: the `ORIGINATOR-ID` and the
`CLUSTER-LIST`.

When a route is sent, its attribute list must be altered to encode those two attribute.
The plugin must be inserted on `BGP_ENCODE_ATTR`. The plugin will first retrieve the
plugin via the ``get_attr`` helper function. Then, it encodes the attribute to be sent
through the network with an internal buffer. When it has been filled, the plugin call the
helper function ``write_to_buffer`` to copy the plugin internal buffer.

A plugin must also be set on the "decoding" part of attributes, so that the BGP
implementation recognize them. This is done by using the `BGP_DECODE_ATTR` insertion point.
The buffer containing the network representation of the attribute will be passed to the
plugin. As request, the buffer will be copied from the host to the plugin via the
built-in helper function ``bpf_get_args``.

One "parser" plugins has been written, another plugin must be set on the
`BGP_INBOUND_PRE_FILTER` insertion point. Given the route and its attributes, the plugin
will use the helper function, get_attribute_by_code, to check if the `ORIGINATOR_ID` and
the `CLUSTER_LIST` attributes are in the list of attributes. If it is the case, the
plugin will first compare the Originator ID with the Router ID thanks the helper function
``get_local_router_id``. If it is a mismatch, the plugin check for its `CLUSTER_ID` into
the `CLUSTER_LIST`. If it is a match, then the plugin returns `REJECT`. The host
implementation knows that the route must not be added to the Adj-RIB-in. If
`ACCEPT` is returned, the host BGP instance will treat the route as valid, and continue
its execution.

The BGP decision process must also be altered so that the Router-ID comparison
must take the `ORIGINATOR_ID` of the attribute instead of the remote router iD.
Furthermore, an extra step must be added right after this step to take the route
having the lowest cluster_list length. The local router cluster id, and the remote router
ID can be retrieved with `get_cluster_id` and `get_remote_router_id` respectively.
The route attributes are accessible through the `get_attribute_by_code` helper function.

Finally, another plugin may be set to the `PRE_OUTBOUND_FILTER` insertion point to check
if the ORIGINATOR_ID of the route attribute is the same as the peer router id the. If so,
the route must be filtered and thus not sent to the remote peer. This last plugin is an
optimisation to not send superfluous route as the router already knows that it has been
originated from them.

RFC4760
=======

This document is about Multiprotocol Extensions (MP) for BGP-4.

Ideally, this plugin should modify the internal representation of plugin memory. So
that the new AFI/SAFI can use the already implemented code for the IPv4 unicast AFI.

However, on both FRRouting and Bird, once the NRLI prefix is decoded, the implementation
directly compare the the received route with the other of the RIB through the BGP
decision process.

For each new NLRI, it is needed to rewrite the whole process from the reception to
the advertisement to the other peers

Upon the decoding of a new route, that we call A, from a given NRLI from the MP_REACH
attribute, the following actions are required to be done.

- ``Pre Inbound Filter``. The route is filtered for AS PATH loop, cluster id etc ...
  This is done via the ``BGP_INBOUND_PRE_FILTER`` function
- ``Inbound filter``. The route must be filtered from the user defined filters
- ``BGP Decision Process``. This is done via attributes
- `` Pre outbound Filter``. If the new NRLI route is chosen, check for AS-PATH LOOP,
  confederation, etc.
- ``Outbound Filter``. User defined filters that check if BGP is allowed to send the
  route to the peer

RFC5492
=======

This document describe how to implement the capability optional parameter inside an
Open BGP message.

The extension alters the way the BGP OPEN message is built. Hence two new insertion points
must be used, one to decode one optional (each time a plugin is called) open parameters and
the other to encode the capability option.

Upon parsing of the capability, the router choose whether or not to continue the session
according to the session type. If the BGP sessions are established to exchange IPv6 unicast
routes, but one on the router cannot parse MultiProtocol extensions, the connexion must be
aborted. The plugin has to call (either a plugin to send a BGP notification, or a function
that does the job)

RFC5291
=======

ORF is required to do several change to the protocol :

First, a new capability must be handled to advertise the willingness of the speaker to
send/receive ORF filters. The plugins decodes each ORF entry, and then store it to a
memory area related to the peer (e.g. memory pool associated for each peer)

Outbound Route Filtering (ORF) is relying on a new BGP ROUTE REFRESH message, so the first
part to do is to handle BGP Route Refresh. The parsing must be revised to handle new
ORF entries. Each ORF entries sent by the peer correspond to a specific outbound filter
to be applied when the router sends its routing table.

Finally, a new plugin must be inserted to the ``BGP_OUTBOUND_PRE_FILTER`` to handle ORF
filters, for a specific peer.

RFC5292
=======

Definition of a new ORF type. RFC5291 must be implemented via plugins. Then, the new
ORF entry can be added to plugins.

RFC6793
=======

AS numbers encoded as 32 bits instead of 16bits.

It consist of a new BGP capability, the addition of two new attributes AS4_PATH
AS4_AGGREGATOR to be retro compatible with OLD BGP speakers

To be compatible with BGP speaker that does not support 4 octets AS numbers,
other plugins must be written to correctly handle the AS_PATH and AS_AGGREGATOR, according
the BGP version

RFC7311
=======

The Accumulated IGP metric is encoded as a new BGP attribute.
It must be then decoded, readvertised to/from other peers and included on the BGP
decision process.
--> get IGP information

RFC7313
=======

Enhanced route refresh :

1/ Adds new capability
    See before

2/ Needs to get information from the routing table to mark routes as "stale" (graceful restart)
    This is done via an helper function

3/ Handle RR Message
    Through the use of the insertion point that parse a new type of BGP Message.
    To handle base Route refresh, the two BGP speakers need to support it. A
    mechanism must be provided to plugins to regenerate the update of the entire
    routing table. An helper function needs to be created to ask for the host BGP
    implementation to send a message through the network.

RFC7911
=======

Add path
1/ Handle capability
2/ Reparse the base NRLI + other NRLI to add the ADDPATH ID
3/ Adding this information to the {ADJ-}?RIB{-In,-Out}?
4/ When advertising routes to the prefix, select on base of a plugin

RFC7947
=======
Route Server
~RR in eBPG mode

Accept all update message,
Do not modify the NEXT_HOP
No AS prepending --> no check for client route server if leftmost as is not the one sent
Propagation of MED

~~ Copy of the UPdate to hte clients


RFC8092
=======

Large Community, see how to parse and encore other attributes

RFC8654
=======
64K buffer
Maybe impossible