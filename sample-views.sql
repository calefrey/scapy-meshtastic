-- NodeView source

CREATE VIEW NodeView as
SELECT
	n._id,
	n.shortName,
	n.longName,
	n.role,
	n.hwModel,
	datetime(n._timestamp, 'unixepoch') lastheard,
	json_extract(n.packet, '$.hop_start') hop_limit

from
	(select * from
	nodes n
	inner JOIN "data" d on d.src = n._id
	where
		d.dst == '!ffffffff' --only want broadcasts
	order by d._timestamp desc) as n -- first sort by the last-received time to ensure it's the newest data
group by _id; --only want one per ID

-- PacketView source

CREATE VIEW PacketView as
SELECT
	datetime(data._timestamp, 'unixepoch') frametime,
	src,
	nodes.longName,
	dst,
	packet_id,
	packet,
	payload,
	data.appname,
	data.appdata
from
	data
LEFT JOIN nodes on
	nodes._id = data.src
group by
	src,
	packet_id
order by
	frametime asc
