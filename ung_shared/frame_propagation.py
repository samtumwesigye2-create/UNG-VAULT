"""Shared UNG reference-frame and benign signal-propagation primitives.
4x4 homogeneous transforms; units are caller-defined but must be consistent.
Propagation supports communications/sensor timing and visualization only.
"""
from __future__ import annotations
from dataclasses import dataclass
from math import sqrt
from typing import Iterable

C_MPS = 299_792_458.0

def identity4():
    return [[1.,0.,0.,0.],[0.,1.,0.,0.],[0.,0.,1.,0.],[0.,0.,0.,1.]]

def matmul(a,b):
    return [[sum(a[i][k]*b[k][j] for k in range(4)) for j in range(4)] for i in range(4)]

def transform_point(t,p):
    v=[float(p[0]),float(p[1]),float(p[2]),1.]
    q=[sum(t[i][j]*v[j] for j in range(4)) for i in range(4)]
    w=q[3] or 1.
    return [q[0]/w,q[1]/w,q[2]/w]

def translation(x,y,z):
    t=identity4(); t[0][3]=x; t[1][3]=y; t[2][3]=z; return t

def rigid_inverse(t):
    r=[[t[i][j] for j in range(3)] for i in range(3)]
    out=identity4()
    for i in range(3):
        for j in range(3): out[i][j]=r[j][i]
    p=[t[i][3] for i in range(3)]
    for i in range(3): out[i][3]=-sum(out[i][j]*p[j] for j in range(3))
    return out

@dataclass(frozen=True)
class FrameTransform:
    source: str
    destination: str
    matrix: list
    timestamp: str|None=None
    version: str="ung-frame-v1"

class FrameGraph:
    def __init__(self): self.edges={}
    def add(self,x:FrameTransform):
        self.edges[(x.source,x.destination)]=x
        self.edges[(x.destination,x.source)]=FrameTransform(x.destination,x.source,rigid_inverse(x.matrix),x.timestamp,x.version)
    def convert(self,p,source,destination):
        if source==destination:return list(p)
        seen={source}; queue=[(source,identity4())]
        while queue:
            cur,acc=queue.pop(0)
            for (a,b),edge in self.edges.items():
                if a!=cur or b in seen: continue
                nxt=matmul(edge.matrix,acc)
                if b==destination:return transform_point(nxt,p)
                seen.add(b);queue.append((b,nxt))
        raise KeyError(f"no frame path: {source} -> {destination}")

def distance(a,b):
    return sqrt(sum((float(a[i])-float(b[i]))**2 for i in range(3)))

def propagation_delay(distance_m, speed_mps=C_MPS):
    if distance_m<0 or speed_mps<=0: raise ValueError("distance must be >=0 and speed >0")
    return distance_m/speed_mps

def round_trip_delay(distance_m, speed_mps=C_MPS):
    return 2*propagation_delay(distance_m,speed_mps)

def wavefront_radius(elapsed_s, speed_mps=C_MPS):
    return max(0.,elapsed_s)*speed_mps

def propagation_product(origin_m,destination_m,speed_mps=C_MPS):
    d=distance(origin_m,destination_m)
    return {"distance_m":d,"one_way_delay_s":propagation_delay(d,speed_mps),
            "round_trip_delay_s":round_trip_delay(d,speed_mps),
            "speed_mps":speed_mps,"provenance":"DERIVED",
            "use":"communications/sensor timing and visualization"}
