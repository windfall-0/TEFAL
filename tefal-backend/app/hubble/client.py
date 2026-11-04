"""Hubble Relay 클라이언트 (④ 네트워크 · 정책에 막힌 흐름, 5.5).

Relay는 gRPC만 준다(`Observer.GetFlows`). 이 클러스터의 Relay는 서버 TLS를 끈 상태라
(`disable-server-tls: true`) 평문 채널로 붙는다. 흐름은 각 노드 Hubble 링 버퍼에 남은 것만 나온다.
"""

import logging

import grpc
from google.protobuf.timestamp_pb2 import Timestamp

from app.hubble.pb.flow import flow_pb2
from app.hubble.pb.observer import observer_pb2, observer_pb2_grpc

log = logging.getLogger(__name__)

MAX_FLOWS = 2000  # 한 번에 받을 최대 흐름 수 (Relay가 노드 버퍼를 합쳐서 준다)


class HubbleError(Exception):
    pass


def _ts(ms: int) -> Timestamp:
    t = Timestamp()
    t.FromMilliseconds(ms)
    return t


class HubbleClient:
    def __init__(self, addr: str, timeout: float = 10.0) -> None:
        self._channel = grpc.aio.insecure_channel(addr)
        self._stub = observer_pb2_grpc.ObserverStub(self._channel)
        self._timeout = timeout

    async def close(self) -> None:
        await self._channel.close()

    async def dropped_flows(self, namespace: str, from_ms: int, to_ms: int) -> list[flow_pb2.Flow]:
        """namespace의 pod가 출발지나 목적지인 DROPPED 흐름."""
        dropped = [flow_pb2.DROPPED]
        req = observer_pb2.GetFlowsRequest(
            number=MAX_FLOWS,
            since=_ts(from_ms),
            until=_ts(to_ms),
            whitelist=[
                flow_pb2.FlowFilter(verdict=dropped, source_pod=[f"{namespace}/"]),
                flow_pb2.FlowFilter(verdict=dropped, destination_pod=[f"{namespace}/"]),
            ],
        )
        flows = []
        try:
            async for resp in self._stub.GetFlows(req, timeout=self._timeout):
                if resp.HasField("flow"):
                    flows.append(resp.flow)
        except grpc.aio.AioRpcError as e:
            raise HubbleError(f"GetFlows: {e.code().name}") from e
        return flows


# ---- 표 만들기 ----

def _endpoint(ep: flow_pb2.Endpoint, ip: str, names: list[str] | None = None) -> str:
    if ep.pod_name:
        return f"{ep.namespace}/{ep.pod_name}" if ep.namespace else ep.pod_name
    if names:
        return names[0]  # DNS 이름 (FQDN 정책)
    for label in ep.labels:  # world, host 같은 예약 identity
        if label.startswith("reserved:"):
            return f"{ip} ({label.removeprefix('reserved:')})" if ip else label.removeprefix("reserved:")
    return ip or "?"


def _port(f: flow_pb2.Flow) -> str:
    l4 = f.l4
    for proto in ("TCP", "UDP", "SCTP"):
        if l4.HasField(proto):
            return f"{proto} {getattr(l4, proto).destination_port}"
    if l4.HasField("ICMPv4") or l4.HasField("ICMPv6"):
        return "ICMP"
    return ""


def drop_rows(flows: list[flow_pb2.Flow], limit: int) -> list[dict]:
    """같은 출발지→목적지·사유는 하나로 합친다. 최근 순."""
    rows: dict[tuple, dict] = {}
    for f in flows:
        src = _endpoint(f.source, f.IP.source)
        dst = _endpoint(f.destination, f.IP.destination, list(f.destination_names))
        port = _port(f)
        reason = flow_pb2.DropReason.Name(f.drop_reason_desc) if f.drop_reason_desc else ""
        policies = sorted({p.name for p in (*f.egress_denied_by, *f.ingress_denied_by) if p.name})
        key = (src, dst, port, reason)
        t = f.time.ToMilliseconds()
        row = rows.get(key)
        if row is None:
            rows[key] = {
                "src_pod": src,
                "dst": f"{dst} · {port}" if port else dst,
                "verdict": "DROPPED",
                "reason": reason,
                "direction": flow_pb2.TrafficDirection.Name(f.traffic_direction),
                "policy": ", ".join(policies),
                "count": 1,
                "time_ms": t,
            }
        else:
            row["count"] += 1
            row["time_ms"] = max(row["time_ms"], t)
            if policies and not row["policy"]:
                row["policy"] = ", ".join(policies)
    return sorted(rows.values(), key=lambda r: -r["time_ms"])[:limit]
