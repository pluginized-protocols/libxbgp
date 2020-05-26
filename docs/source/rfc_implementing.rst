================================================
Implementing RFCs from minimal BGP with plugins
================================================

This section explains how to implement RFCs that add new extensions with eBPF plugins
to a minimal BGP implementation as defined by rfc4271.

This work tries to propose multiple changes that have to be made inside the host
implementation of BGP to execute a plugin. We would also like the same plugin
can be executed independently of the base BGP implementation. Hence the need to
both declare a common set of insertion points and API functions usable through plugins.

Insertion Point
===============
The BGP implementation must propose those insertion points, so that, plugins can be
hooked to them. Some of them are currently inserted in both FRRouting and Bird while others
are not inserted yet. These latter will be used to support more extensions. They are listed
here to give an overview of what could be the final BGP API for plugin.

Insertion points not implemented is followed by the `[Not Implemented]` label.

`BGP_ENCODE_ATTR`
    This insertion point handles the encoding of all attributes related to a given BGP
    route. Arguments passed through the plugin are the current attribute to be encoded and
    the buffer dedicated to the attribute of the BGP UPDATE message. The latter argument is
    hidden from the plugin since multiple implementations can use different representations.
    Accessing to this buffer must be done via helper functions.

`BGP_DECODE_ATTR`
    This insertion point will be used for plugin that wants to decode a given attribute.
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

`BGP_DECODE_REACH_NLRI` [Not Implemented]
    This insertion point decode a buffer containing all the NRLI encoded to a BGP UPDATE
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

`BGP_DECODE_WITHDRAW_NLRI` [Not Implemented]
    This insertion point is used to decode prefixes that need to be withdrawn.
    The following arguments must be passed through the plugin :

    - The peer information
    - The AFI
    - The SAFI
    - The buffer containing the unfeasible routes
    - The buffer length

`BGP_INBOUND_PRE_FILTER`
    This insertion point is used to either accept or not the route into the local router.
    Plugins are executed just before user defined inbound filters.

    Arguments involved to this insertion point:

    - The current route prefix
    - The peer information from which the router received the route
    - List of route attributes

`BGP_INBOUND_FILTER`
    The insertion point executes user defined filters when the route is received
    on the inbound side of the router.

    Arguments are the same as ``BGP_INBOUND_PRE_FILTER``

`BGP_OUTBOUND_PRE_FILTER`
    This insertion point is used to check whether or not the route must be announced to
    the remote peer. As ``BGP_INBOUND_PRE_FILTER``, plugins attached to it are executed
    just before user defined outbound filters. This insertion point can also manipulate attributes
    such as adding or modifying the attribute associated with the route.

    Arguments needed for this insertion point are:

    - The current route prefix
    - The peer information from which the router received the route
    - The peer information to which the router is going to send the route
    - List of route attributes

`BGP_OUTBOUND_FILTER`
    Executes the user defined filters when the route is received on the outbound side of the
    router.

    Arguments are the same as ``BGP_OUTBOUND_PRE_FILTER``

`BGP_DECISION_PROCESS`
    Insertion point to reimplement the BGP decision process.
    TODO, dispatch function to invoke either a new
    The decision process insertion point has multiple arguments:

    - The old route
    - The new received route

    The two received routes both contain :

    - The peer from which the router has received it
    - The current prefix to process
    - The attribute list related to the path

`BGP_RECEIVED_MESSAGE`
    Used to decode a given type of BGP message. When the BGP header been parsed (i.e., the
    marker, the length and the type) the whole buffer containing the actual message
    is returned to the plugin. It can then parse a new BGP message such as
    route refresh.

    Argument to be given to the plugin in charge of decoding an incoming message is

    - The peer information
    - The type code for the BGP Message
    - The buffer encoded in network format

    This insertion point is essentially used to decode new BGP messages (other than
    OPEN, UPDATE, KEEPALIVE and NOTIFICATION). However, the host implementation could
    decide to completely override the code of the actual implementation. However, we
    do not recommend putting this kind of insertion point to decode a whole BGP
    UPDATE. We provide other insertion points that handle parts of a BGP update.

`BGP_ENCODE_MESSAGE`
    Used to encode a whole new BGP message (preferably other than OPEN, KEEPALIVE,
    UPDATE and NOTIFICATION) in network format. The argument given to this insertion
    point is

    - The peer information
    - The kind of BGP update to encode
    - [AS HIDDEN] The host buffer that will be transmitted to the peer

`BGP_OPEN_DECODE_OPT_PARAM` [Not Implemented]
    This insertion point decode one specific optional parameter carried into the BGP OPEN
    message. The arguments are

    - The peer information
    - The optional parameter type
    - The optional parameter length
    - A buffer containing the parameter in network format

`BGP_OPEN_ENCODE_OPT_PARAM` [Not Implemented]
    This insertion point is used to add an optional parameter to the open message.
    One pluglet correspond to one optional parameter. Its arguments are:

    - The peer information
    - [AS HIDDEN] The buffer that will be written when `write_to_buffer` is called.

Helper Function
===============
Helper functions are mostly designed to retrieve (resp. store) data from (resp. to) the
host implementation. As for insertion points, some functions are not yet implemented in both
FRRouting and Bird. Those functions are, however, listed to provide an overview of the final
API.

Since plugins can be executed on different BGP implementation, plugins need to manipulate
abstract structures. For example, it is needed to define an abstract structure representing
a prefix, whatever its representation inside the host implementation. Hence all the helper
functions
are expected to receive or return a common representation. The API must also define these
structures in parallel.

`int add_attr(uint code, uint flags, uint16_t length, uint8_t *decoded_attr)`
    Adds the attribute specified onto its arguments to the route the plugin is currently
    processing. The route is not specified since the plugin calling this function assumes
    it only processes one route at once.

`int set_attr(struct path_attribute *attr)`
    The function is quite identical as `add_attr` but it can also be used to update attributes
    already set to a specific route.

`struct path_attribute *get_attr()`
    Gets the current attribute the plugins are processing. To use this function,
    one of the plugin's arguments must be the attribute. If multiple attributes are
    given to the plugin, check ``get_attr_by_code``

`struct ubpf_peer_info *get_peer_info()`
    Retrieve information related to the peer to which the route is expected to be announced.
    The structure returned to the plugin contains:

    - The remote AS
    - The emote Router ID
    - The peer type, whether it is an iBGP or eBGP session
    - The remote address used to establish the BGP session with the peer
    - The local router ID and the local AS

`struct ubpf_peer_info *get_src_peer_info()`
    Retrieve information related to the peer that has announced the route to the current
    router. The structure returned to the plugin contains the same information as the previous
    function.


`int write_to_buffer(uint8_t *buf, size_t len)`
    The function copies the content of ``buf`` up to len bytes into the internal buffer
    of the host implementation passed as hidden arguments to the plugin. Only one internal
    buffer must be provided to the hidden argument of the plugin.

`void *bpf_get_args(bpf_full_args_t *args, int pos_id)`
    Built-in function that retrieves the argument from the host implementation.
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
    the argument. It will then copy the content of the pointer ``arg`` by ``len`` bytes
    to an allowed plugin memory area.


`int add_route_rib(struct bgp_route *rte)` [Not implemented yet]
    Adds a new route into the BGP RIB of the host implementation.
    The structure passed to the function has the following fields:

    .. code-block:: c

        struct bgp_route {
            struct ubpf_prefix pfx; // prefix that is reachable (support for AFI/SAFI)
            int attr_nb; // number of attributes
            struct path_attribute *attr; // attribute list
            struct ubpf_peer_info *peer_info; // information related to the peer having announced the route
            uint32_t type; // CONNECTED, STATIC, IGP, BGP
        };

`int rib_iterator(/* to be determined */)` [Not implemented yet]
    This function will iterate through specific routes matching a given pattern passed to the
    argument of this function. Could be used for example on import/export filters to limit the
    number of routes to the same prefix. It can also be used to check if there is a more general
    route to the destination.

`int parsed_nrli(struct ubpf_prefix *pfx)` [Not Implemented Yet]
    Used to inform the protocol that a prefix has been parsed.
    For each update message, the host implementation keeps a list (or a user-defined
    date structure) that will be filled by this helper function. When all NRLI from
    an update message has been decoded, the host implementation will use this list
    to continue its execution and then continue the BGP UPDATE processing.
    To be able to use this function, the base implementation must be a little
    bit altered to allow using the ``struct ubpf_prefix`` to represent a prefix into
    memory. Hence, every function using an internal representation of the prefix must be
    modified to use this custom defined function.

`struct path_attribute *get_attr_from_code(uint8_t code)`
    Returns the attribute related to the code given to the arguments of function. This function is called when
    the insertion point is on a location involving the whole attribute list of the route.

`struct path_attribute *get_attr_by_code_from_rte(uint8_t code, int args_rte)`
    Same as above, but the function is used on the BGP decision process when two
    routes are compared together.


To be compatible with multiple implementations, the functions listed above are relying on
abstract structures that plugins can manipulate without being linked to a specific BGP
implementation. When a function returns a specific structure, it must "transform" the internal
representation of the host implementation of the abstract representation that can be uniquely
manipulated inside plugins. The opposite way is also valid. If the plugin adds new data to the
host implementation, the function has to convert to the internal representation of the host
implementation.


The next section is describing how to implement RFC that extends the base definition of BGP.
Currently, we implemented :

- Route Reflectors
- Extended Communities (not handled by Bird)
- A modified version of the MED computation
- Replacing the MED decision step by the geographical distance between the router that announced the
  prefix and the one computing its best route toward the destination.

Working Use Cases
=================

RFC4456
-------

This document describes how to define route reflectors and confederations.

Route Reflectors introduce new route attributes: the `ORIGINATOR-ID` and the
`CLUSTER-LIST`.

When a route is sent, its attribute list must be altered to encode those two attribute.
The plugin must be inserted in `BGP_ENCODE_ATTR`. The plugin will first retrieve the
plugin via the ``get_attr`` helper function. Then, it encodes the attribute to be sent
through the network with an internal buffer. When it has been filled, the plugin call the
helper function ``write_to_buffer`` to copy the plugin internal buffer.

A plugin must also be set on the "decoding" part of attributes, so that the BGP
implementation recognize them. This is done by using the `BGP_DECODE_ATTR` insertion point.
The buffer containing the network representation of the attribute will be passed to the
plugin. Upon request, the buffer will be copied from the host to the plugin via the
built-in helper function ``bpf_get_args``.

Once "parser" plugins have been written, another plugin must be set on the
`BGP_INBOUND_PRE_FILTER` insertion point. Given the route and its attributes, the plugin
will use the helper function, get_attribute_by_code, to check if the `ORIGINATOR_ID` and
the `CLUSTER_LIST` attributes are in the list of attributes. If it is the case, the
plugin will first compare the Originator ID with the local Router ID that can be retrieved with
the helper function `get_peer_info`.
If it is a mismatch, the plugin check for its `CLUSTER_ID` into
the `CLUSTER_LIST`. If it is a match, then the plugin returns `REJECT`. The host
implementation knows that the route must not be added to the Adj-RIB-in. If
`ACCEPT` is returned, the host BGP instance will treat the route as valid, and continue
its execution.

The BGP decision process must also be altered so that the Router-ID comparison
must take the `ORIGINATOR_ID` of the attribute instead of the remote router iD.
Furthermore, an extra step must be added just after this step to take the route
having the lowest cluster_list length. The local router cluster id, and the remote router
ID can be retrieved with `get_peer_info`.
The route attributes are accessible through the `get_attribute_by_code` helper function.

Finally, another plugin may be set to the `PRE_OUTBOUND_FILTER` insertion point to check
if the ORIGINATOR_ID of the route attribute is the same as the peer router id the. If so,
the route must be filtered and thus not sent to the remote peer.
This plugin must also check if the route comes from a client or a non-client, to decide to export
the route to its neighbors.
Before returning, and if the plugin accepts the route, the attributes ORIGINATOR_ID and
CLUSTER_LIST must be altered.

For now, route reflectors are knowing their clients with an array directly hardcoded inside the
source code of the plugin. In the future, we will add a manifest that will contain the data
that can be retrieved inside the plugin with helper function.

RFC4360
-------

This document describes the extended community attribute, which is a new type of optional transitive
attribute.

The purpose of this new attribute is the same as the COMMUNITY attribute. However each
EXTENDED COMMUNITY is represented with 64 bits instead of 32 bits.

To implement it with plugins, it is required to encode and decode this new attribute received from
an UPDATE message. Hence, one plugin must be set inside the `BGP_PRE_INBOUND_FILTER` to add the
attribute to the path. The other plugin is set on the `BGP_PRE_OUTBOUND_FILTER` to encode this
new attribute to an UPDATE message.

With these two plugins, other plugins can retrieve it with the function `get_attr_from_code` to
do some computation with the attribute. The function set_attr can be used to add or remove
communities.


Adapting the MED
----------------

Changing the MED attribute can avoid side effects such as routing instabilities.
Let us consider the following example :

.. code-block::

              +----------------------------------------------------------------------------------+
              | AS 0        +--------+                                                           |
              |             |        |         +---------------------+        +-------+          |
              |   +---------+   R2   +---+     |                     |        |  R4   |          |      +-----------------+
              |   |         |        |   |     |                     |    +---+       +---------------->+                 |
              |   |         +--------+   |     |                     |    |   |       |          |      |                 |
              | +-+--+                   +-----+      Internal       +----+   +-------+          |      |                 |
              | |    |                         |      Network        |                           |      |      AS 1       |
    P +---------> R1 |                         |      Topology       |                     +----------->+                 |
              | |    |                   +-----+                     +----+                |     |      |                 |
              | +-+--+      +--------+   |     |                     |    |   +-------+    |     |      |                 |
              |   |         |        |   |     |                     |    |   |       |    |     |      +-----------------+
              |   +---------+   R3   +---+     +---------------------+    +---+  R5   +----+     |
              |             |        |                                        |       |          |
              |             +--------+                                        +-------+          |
              +----------------------------------------------------------------------------------+

The MED is usually reflecting the IGP cost to reach a given prefix. It signals to the peer
that AS0 would like that incoming traffic goes through the router that has advertised the lowest
MED value. A small
modification of the path cost inside the intra-network results to a readvertisement of the MED for
every prefix impacted by this such modification. In some cases, this IGP cost update won't change
the choice of the preferred router for the incoming traffic. This is therefore useless to
advertise again the unmodified path.
To avoid these route oscillations, the MED can rely on both geographical coordinates of the router
and the prefix. Each route carries a new attribute containing the geographical coordinate of
the prefix whereas the router contains its own geographical position. When advertising the prefix
to another AS, the edge router compute the Euclidean distance with its own coordinates and the
router that advertised the prefix within the AS. This is done on export filter part of the
extension only if the peer is on a different AS.
If the router injects the prefix through BGP (i.e., the prefix is local to the router or
received from an eBGP session), it must
add its own geographical position to the attributes of the path. Step made on import filter side
of the router (Phase 1).


Compare the Euclidean Distance on the MED Step
----------------------------------------------

The MED is used by a network operator to announce to the other AS in which router the incoming
traffic needs to follow. We propose not to use the real purpose of the MED. Instead, we will choose
to compute the Geographical distance from the router having originated the prefix
to the router computing its best route.
This use case shows that we can easily add a new attribute inside BGP and make computations with,
for example inside the BGP decision process.

Its functioning is very basic. Instead of taking the MED attribute during the BGP decision process,
we use the new attribute carrying the geographic coordinate of the originator router. The router
computes the Euclidean distance between itself and the coordinates contained in this new attribute.


Not Implemented Use Case
========================

RFC4760
-------

This document is about Multiprotocol Extensions (MP) for BGP-4.

Ideally, this plugin should modify the internal representation of plugin memory. So
that the new AFI/SAFI can use the already implemented code for the IPv4 unicast AFI.

If the host implementation only supports IPv4 unicast, then for each new NLRI,
it is needed to rewrite the whole process from the reception to
the advertisement to the other peers since the host implementation cannot handle with the
new AFI/SAFI prefix.

Upon the decoding of a new route, from a given NRLI of the MP_REACH
attribute, all the "update procedure" has to be reimplemented from scratch.

On Bird and FRRouting, once the route has been decoded, they will directly call functions
update its routing table. The following event is then triggered :

- ``Pre Inbound Filter``. The route is filtered for AS PATH loop, cluster id etc ...
- ``Inbound filter``. The route must be filtered from the user defined filters
- ``BGP Decision Process``.
- `` Pre outbound Filter``.
- ``Outbound Filter``. User-defined filters that check if BGP is allowed to send the
  route to the peer.

Those events are triggered if the host implementation recognizes the AFI/SAFI. However, for a
new one, they need to be fully reimplemented with plugins. Plugins cannot rely on the host source
code. For example, the BGP decision process must be reimplemented even though nothing has been
altered, because the prefix representation is different than the ones supported by the host
implementation.

Another approach is to slightly modify the base implementation to support
different AFI/SAFI. In this case, the implementation of plugins will be easier. There is no need
to fully reimplement everything from scratch. If we take our example with the BGP decision process,
nothing is needed to be done since the host implementation can handle different AFI/SAFI prefixes.

If the base BGP implementation has a RIB that supports different type of AFI/SAFI it is only
required to decode and encode the new AFI/SAFI with plugins set on the `BGP_DECODE_ATTR` and
`BGP_ENCODE_ATTR` insertions points respectively.

RFC5492
-------

This document describes how to implement the capability optional parameter inside an
Open BGP message.

The extension alters the way the BGP OPEN message is built. Hence two new insertion points
must be used, one to decode one optional (each time a plugin is called) open parameters and
the other to encode the capability option.

Upon parsing of the capability, the router choose whether or not to continue the session
according to the session type. If the BGP sessions are established to exchange IPv6 unicast
routes, but one of the routers cannot parse MultiProtocol extensions, the connection must be
aborted. The plugin has to call (either a plugin to send a BGP notification, or a function
that does the job)

RFC5291
-------

ORF is required to make several changes to the protocol :

First, a new capability must be handled to advertise the willingness of the speaker to
send/receive ORF filters. The plugin decodes each ORF entry, and then store it to a
memory area related to the peer (e.g., memory pool associated with each peer).

Outbound Route Filtering (ORF) is relying on a new BGP ROUTE REFRESH message, so the first
part to do is to handle BGP Route Refresh. The parsing must be revised to handle new
ORF entries. Each ORF entries sent by the peer correspond to a specific outbound filter
to be applied when the router sends its routing table.

Finally, a new plugin must be inserted to the ``BGP_OUTBOUND_PRE_FILTER`` to handle ORF
filters, for a specific peer.

RFC5292
-------

Definition of a new ORF type. RFC5291 must be implemented via plugins. Then, the new
ORF entry can be added to plugins.

RFC6793
-------

AS numbers encoded as 32 bits instead of 16bits.

It consists of a new BGP capability, the addition of two new attributes AS4_PATH
AS4_AGGREGATOR to be retro compatible with OLD BGP speakers

To be compatible with BGP speakers that do not support 4 octets AS numbers,
other plugins must be written to correctly handle the AS_PATH and AS_AGGREGATOR, according to
the BGP version.

Each time the protocol has to deal with AS PATH (typically on import/export + decision process)
a plugin must be set to handle the 32-bit number.

RFC7311
-------

The Accumulated IGP metric is encoded as a new BGP attribute.
It must be then decoded, readvertised to/from other peers and included on the BGP
decision process.
--> get IGP information, not possible with plugins now

RFC7313
-------

Enhanced Route refresh :

1/ Adds new capability
    See before

2/ Needs to get information from the routing table to mark routes as "stale" (graceful restart)
    This is done via a helper function

3/ Handle RR Message
    Through the use of the insertion point that parses a new type of BGP Message.
    To handle base Route refresh, the two BGP speakers need to support it. A
    mechanism must be provided to plugins to regenerate the update of the entire
    routing table. A helper function needs to be created to ask for the host BGP
    implementation to send a message through the network.

RFC7911
-------

Add path
1/ Handle capability
2/ Reparse the base NRLI + other NRLI to add the ADDPATH ID
3/ Adding this information to the {ADJ-}?RIB{-In,-Out}?
4/ When advertising routes to the prefix, select on the base of a plugin

This use case is complicated if the host BGP doesn't support multiple AFI/SAFI.

RFC7947
-------
Route Server
~RR in eBGP mode

Accept all update message,
Do not modify the NEXT_HOP
No AS prepending --> no check for clients route server if leftmost AS is not the one sent
Propagation of MED

~~ Copy of the Update to the clients


RFC8092
-------

Large Community, see how to parse and encore other attributes (Same as Extended Communities)

RFC8654
-------
64K buffer instead of 4K buffers
Maybe impossible because plugins have to change the internal representation of the host implementation
and its structure.