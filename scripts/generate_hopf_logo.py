#!/usr/bin/env python3
"""
Hopf fibration logo SVG — Niles Johnson linked-circle style.

Stereographic Hopf fibers as tubular circles on nested tori, depth-sorted
with simple tube shading, bounding circle, exceptional vertical fiber.

  python3 scripts/generate_hopf_logo.py
"""

from __future__ import annotations

import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "assets" / "hopf-fibration.svg"

SIZE = 1100
MARGIN = 70

# Oblique view matching the teaching figure (axis vertical-ish, nest from the side)
ROT_X = math.radians(20)
ROT_Y = math.radians(-28)
ROT_Z = math.radians(4)

# Nested tori (outer → inner); denser fibers so each shell reads as a torus
ETA_VALUES = [1.05, 0.88, 0.72, 0.56, 0.42, 0.30]
FIBERS_PER_LAYER = [16, 15, 14, 13, 12, 11]

# Color by Hopf base longitude (φ); η only modulates lightness slightly.
# This matches Niles Johnson's S²→hue mapping (rainbow around each torus).
def fiber_color(eta: float, phi: float, eta_min: float, eta_max: float) -> tuple[float, float, float]:
    # Hue sweeps with φ; shift slightly with η so nested shells don't alias
    t = (eta - eta_min) / max(eta_max - eta_min, 1e-9)
    hue = (math.degrees(phi) + 40 + 25 * t) % 360
    sat = 0.72 - 0.08 * t
    light = 0.52 + 0.10 * (1.0 - t)
    return hue, sat, light

SAMPLES = 144
ARC = 8
TUBE = 5.8
LIGHT = (0.5, 0.85, 0.35)
CLIP_R = 4.5  # drop stereo outliers beyond this before framing


def hsl(h: float, s: float, l: float) -> str:
    h %= 360
    s = max(0.0, min(1.0, s))
    l = max(0.0, min(1.0, l))
    c = (1 - abs(2 * l - 1)) * s
    x = c * (1 - abs((h / 60) % 2 - 1))
    m = l - c / 2
    if h < 60:
        r, g, b = c, x, 0.0
    elif h < 120:
        r, g, b = x, c, 0.0
    elif h < 180:
        r, g, b = 0.0, c, x
    elif h < 240:
        r, g, b = 0.0, x, c
    elif h < 300:
        r, g, b = x, 0.0, c
    else:
        r, g, b = c, 0.0, x
    return (
        f"#{int(round((r + m) * 255)):02x}"
        f"{int(round((g + m) * 255)):02x}"
        f"{int(round((b + m) * 255)):02x}"
    )


def rotate(p: tuple[float, float, float]) -> tuple[float, float, float]:
    x, y, z = p
    cz, sz = math.cos(ROT_Z), math.sin(ROT_Z)
    x, y = cz * x - sz * y, sz * x + cz * y
    cy, sy = math.cos(ROT_Y), math.sin(ROT_Y)
    x, z = cy * x + sy * z, -sy * x + cy * z
    cx, sx = math.cos(ROT_X), math.sin(ROT_X)
    y, z = cx * y - sx * z, sx * y + cx * z
    return x, y, z


def hopf_stereo(eta: float, phi: float, theta: float) -> tuple[float, float, float]:
    c, s = math.cos(eta), math.sin(eta)
    x = c * math.cos(theta)
    y = c * math.sin(theta)
    z = s * math.cos(theta + phi)
    w = s * math.sin(theta + phi)
    d = 1.0 - w
    if abs(d) < 1e-9:
        d = 1e-9 if d >= 0 else -1e-9
    return x / d, y / d, z / d


def fit_circle(pts: list[tuple[float, float, float]]):
    a, b, c = pts[0], pts[len(pts) // 3], pts[(2 * len(pts)) // 3]

    def sub(p, q):
        return (p[0] - q[0], p[1] - q[1], p[2] - q[2])

    def cross(p, q):
        return (
            p[1] * q[2] - p[2] * q[1],
            p[2] * q[0] - p[0] * q[2],
            p[0] * q[1] - p[1] * q[0],
        )

    def dot(p, q):
        return p[0] * q[0] + p[1] * q[1] + p[2] * q[2]

    def norm(p):
        return math.sqrt(dot(p, p)) or 1.0

    def scale(p, s):
        return (p[0] * s, p[1] * s, p[2] * s)

    ab, ac = sub(b, a), sub(c, a)
    n = cross(ab, ac)
    n = scale(n, 1.0 / norm(n))
    ab2, ac2 = dot(ab, ab), dot(ac, ac)
    abxac = cross(ab, ac)
    abxac2 = dot(abxac, abxac)
    if abs(abxac2) < 1e-12:
        center = (
            sum(p[0] for p in pts) / len(pts),
            sum(p[1] for p in pts) / len(pts),
            sum(p[2] for p in pts) / len(pts),
        )
        r = sum(norm(sub(p, center)) for p in pts) / len(pts)
        u = scale(ab, 1.0 / norm(ab))
        v = scale(cross(n, u), 1.0 / norm(cross(n, u)))
        return center, r, u, v
    term1 = scale(cross(abxac, ab), ac2)
    term2 = scale(cross(ac, abxac), ab2)
    o = (
        a[0] + (term1[0] + term2[0]) / (2 * abxac2),
        a[1] + (term1[1] + term2[1]) / (2 * abxac2),
        a[2] + (term1[2] + term2[2]) / (2 * abxac2),
    )
    r = norm(sub(a, o))
    u = scale(sub(a, o), 1.0 / r)
    v = scale(cross(n, u), 1.0 / norm(cross(n, u)))
    return o, r, u, v


def resample_circle(center, radius, u, v, n):
    pts = []
    for i in range(n + 1):
        t = 2 * math.pi * i / n
        ct, st = math.cos(t), math.sin(t)
        pts.append(
            (
                center[0] + radius * (ct * u[0] + st * v[0]),
                center[1] + radius * (ct * u[1] + st * v[1]),
                center[2] + radius * (ct * u[2] + st * v[2]),
            )
        )
    return pts


def shade(h, s, l, nvec):
    nx, ny, nz = nvec
    ln = math.sqrt(nx * nx + ny * ny + nz * nz) or 1.0
    nx, ny, nz = nx / ln, ny / ln, nz / ln
    lx, ly, lz = LIGHT
    ll = math.sqrt(lx * lx + ly * ly + lz * lz)
    lx, ly, lz = lx / ll, ly / ll, lz / ll
    diff = max(0.0, nx * lx + ny * ly + nz * lz)
    body = hsl(h, s, max(0.30, min(0.72, l * (0.58 + 0.6 * diff))))
    shadow = hsl(h, min(1.0, s * 1.08), max(0.20, l * 0.40))
    highlight = hsl(h, max(0.15, s * 0.4), min(0.93, 0.62 + 0.35 * diff))
    return shadow, body, highlight


def to_xy(p, xmin, xmax, ymin, ymax):
    span = max(xmax - xmin, ymax - ymin) or 1.0
    scale = (SIZE - 2 * MARGIN) / span
    cx, cy = (xmin + xmax) / 2, (ymin + ymax) / 2
    return SIZE / 2 + (p[0] - cx) * scale, SIZE / 2 - (p[1] - cy) * scale


def path_d(xy):
    parts = [f"M{xy[0][0]:.2f},{xy[0][1]:.2f}"]
    for x, y in xy[1:]:
        parts.append(f"L{x:.2f},{y:.2f}")
    return "".join(parts)


def main() -> None:
    fibers = []

    eta_min, eta_max = ETA_VALUES[-1], ETA_VALUES[0]
    for li, eta in enumerate(ETA_VALUES):
        nfib = FIBERS_PER_LAYER[li]
        for fi in range(nfib):
            phi = 2 * math.pi * (fi + 0.4 * (li % 2)) / nfib
            h, s, l = fiber_color(eta, phi, eta_min, eta_max)
            raw = [hopf_stereo(eta, phi, 2 * math.pi * i / SAMPLES) for i in range(SAMPLES)]
            # Skip fibers that blow up under stereo
            if any(math.sqrt(p[0] ** 2 + p[1] ** 2 + p[2] ** 2) > CLIP_R for p in raw):
                continue
            center, radius, u, v = fit_circle(raw)
            if radius > CLIP_R * 0.9:
                continue
            circle = resample_circle(center, radius, u, v, SAMPLES)
            cam = [rotate(p) for p in circle]
            cam.append(cam[0])
            fibers.append((cam, h, s, l))

    # Exceptional fiber (line) along stereo axis → vertical-ish after rotation
    extent = 2.8
    axis = [rotate((0.0, 0.0, -extent + 2 * extent * i / 80)) for i in range(81)]
    fibers.append((axis, 210, 0.78, 0.55))

    all_pts = [p for pts, *_ in fibers for p in pts]
    xs, ys = [p[0] for p in all_pts], [p[1] for p in all_pts]
    xmin, xmax, ymin, ymax = min(xs), max(xs), min(ys), max(ys)

    arcs = []
    for pts, h, s, l in fibers:
        for i in range(0, len(pts) - 1, ARC):
            chunk = pts[i : i + ARC + 1]
            if len(chunk) < 2:
                continue
            depth = sum(p[2] for p in chunk) / len(chunk)
            arcs.append((depth, chunk, h, s, l))
    arcs.sort(key=lambda t: t[0])

    xy_all = [to_xy(p, xmin, xmax, ymin, ymax) for p in all_pts]
    bx = sum(p[0] for p in xy_all) / len(xy_all)
    by = sum(p[1] for p in xy_all) / len(xy_all)
    brad = max(math.hypot(x - bx, y - by) for x, y in xy_all) * 1.02

    out = [
        f'  <circle cx="{bx:.2f}" cy="{by:.2f}" r="{brad:.2f}" '
        f'fill="none" stroke="#111" stroke-width="2.4"/>'
    ]

    for _d, chunk, h, s, l in arcs:
        a, b = chunk[0], chunk[-1]
        mid = ((a[0] + b[0]) / 2, (a[1] + b[1]) / 2, (a[2] + b[2]) / 2)
        tx, ty, tz = b[0] - a[0], b[1] - a[1], b[2] - a[2]
        nx = ty * mid[2] - tz * mid[1]
        ny = tz * mid[0] - tx * mid[2]
        nz = tx * mid[1] - ty * mid[0]
        if ny < 0:
            nx, ny, nz = -nx, -ny, -nz
        shadow, body, hi = shade(h, s, l, (nx, ny, nz))
        xy = [to_xy(p, xmin, xmax, ymin, ymax) for p in chunk]
        d = path_d(xy)
        out.append(
            f'  <path d="{d}" fill="none" stroke="{shadow}" stroke-width="{TUBE * 1.2:.2f}" '
            f'stroke-linecap="round" stroke-linejoin="round" opacity=".48"/>'
        )
        out.append(
            f'  <path d="{d}" fill="none" stroke="{body}" stroke-width="{TUBE:.2f}" '
            f'stroke-linecap="round" stroke-linejoin="round" opacity=".97"/>'
        )
        out.append(
            f'  <path d="{d}" fill="none" stroke="{hi}" stroke-width="{TUBE * 0.25:.2f}" '
            f'stroke-linecap="round" stroke-linejoin="round" opacity=".68"/>'
        )

    OUT.write_text(
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{SIZE}" height="{SIZE}" '
        f'viewBox="0 0 {SIZE} {SIZE}" role="img" aria-label="Hopf fibration">\n'
        f"<title>Hopf fibration</title>\n"
        f"<desc>Linked Hopf fibers after stereographic projection "
        f"(Niles Johnson style). Transparent background.</desc>\n"
        + "\n".join(out)
        + "\n</svg>\n"
    )
    print(f"wrote {OUT.relative_to(ROOT)} ({len(fibers)} fibers, {len(arcs)} arcs, {OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
