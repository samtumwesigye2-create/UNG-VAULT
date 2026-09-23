# UNG Frame + Propagation Engine

Shared mathematical foundation for coordinate-frame conversion and benign signal/sensor timing.

- **Frame Engine:** 4×4 homogeneous transforms, composition, inverse rigid transforms, frame graph and point conversion.
- **Propagation Engine:** distance, one-way/round-trip delay, expanding wavefront radius and provenance-tagged propagation products.
- Every integration should retain source frame, destination frame, timestamp/version and uncertainty metadata at the application boundary.

System mappings: CAD uses part→assembly→machine/world; VECTOR uses local/global vector frames; NAVSTAR and CONSTELLATION use spacecraft/orbital/Earth/scene frames; ORION normalizes incoming tracks; KINGSHIP uses building/floor/room/sensor frames; DRACO uses sensor/platform/world frames; WAVE uses device/antenna/network visualization frames; VAULT and PRESIDENT consume normalized products where useful. NEPTUNE use is limited here to coordinate normalization and communications/sensor-report timing.
