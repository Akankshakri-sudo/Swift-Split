/* ============================================================
   SecureVault 3D — the vault core
   A crystalline core that shatters into n encrypted shards and
   reassembles from any k of them. Fully interactive (orbit/zoom),
   with hover picking on individual shards.
   ============================================================ */

import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';

const canvas = document.getElementById('bg3d');

let renderer;
try {
  renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
} catch (err) {
  canvas.remove();                       // no WebGL — CSS gradient stays
  window.SVScene = { shatter() {}, assemble() {}, fail() {}, pulse() {} };
  window.dispatchEvent(new Event('sv-scene-failed'));
  throw err;
}

renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
renderer.toneMapping = THREE.ACESFilmicToneMapping;
renderer.toneMappingExposure = 1.15;

const scene = new THREE.Scene();
scene.fog = new THREE.FogExp2(0x05070f, 0.014);

const camera = new THREE.PerspectiveCamera(55, window.innerWidth / window.innerHeight, 0.1, 300);
camera.position.set(0, 5.5, 30);

const controls = new OrbitControls(camera, canvas);
controls.enableDamping = true;
controls.dampingFactor = 0.06;
controls.enablePan = false;
controls.minDistance = 12;
controls.maxDistance = 70;
controls.autoRotate = false;
if (window.matchMedia('(pointer: coarse)').matches) {
  controls.enableZoom = false;         // keep pinch/scroll for the page
  controls.enableRotate = false;
}

/* ---------------- lights ---------------- */

scene.add(new THREE.AmbientLight(0x3b4a6b, 1.1));

const keyLight = new THREE.DirectionalLight(0xdfeaff, 1.6);
keyLight.position.set(6, 10, 8);
scene.add(keyLight);

const rimLight = new THREE.PointLight(0x818cf8, 24, 90);
rimLight.position.set(-14, 6, -10);
scene.add(rimLight);

/* ---------------- core group ---------------- */

const coreGroup = new THREE.Group();
scene.add(coreGroup);

const coreInner = new THREE.Mesh(
  new THREE.IcosahedronGeometry(3.3, 1),
  new THREE.MeshStandardMaterial({
    color: 0x0c2236, metalness: 0.8, roughness: 0.24,
    emissive: 0x0a3a55, emissiveIntensity: 0.9, flatShading: true,
  })
);
coreGroup.add(coreInner);

const coreShell = new THREE.LineSegments(
  new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(4.15, 1)),
  new THREE.LineBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.5 })
);
coreGroup.add(coreShell);

// soft additive glow behind everything
function glowTexture() {
  const c = document.createElement('canvas');
  c.width = c.height = 256;
  const g = c.getContext('2d');
  const grad = g.createRadialGradient(128, 128, 0, 128, 128, 128);
  grad.addColorStop(0, 'rgba(255,255,255,1)');
  grad.addColorStop(0.25, 'rgba(160,220,255,0.55)');
  grad.addColorStop(0.6, 'rgba(90,160,255,0.16)');
  grad.addColorStop(1, 'rgba(0,0,0,0)');
  g.fillStyle = grad;
  g.fillRect(0, 0, 256, 256);
  return new THREE.CanvasTexture(c);
}
const glow = new THREE.Sprite(new THREE.SpriteMaterial({
  map: glowTexture(), color: 0x38bdf8, transparent: true,
  opacity: 0.33, blending: THREE.AdditiveBlending, depthWrite: false,
}));
glow.scale.setScalar(17);
coreGroup.add(glow);

// orbit rings
const ringMat = new THREE.MeshBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.28 });
const ring1 = new THREE.Mesh(new THREE.TorusGeometry(5.9, 0.018, 8, 140), ringMat);
ring1.rotation.x = Math.PI / 2.25;
const ring2 = new THREE.Mesh(new THREE.TorusGeometry(6.9, 0.012, 8, 140), ringMat.clone());
ring2.material.opacity = 0.16;
ring2.rotation.x = Math.PI / 1.8;
ring2.rotation.y = 0.5;
coreGroup.add(ring1, ring2);

const coreLight = new THREE.PointLight(0x38bdf8, 30, 60);
coreGroup.add(coreLight);

// faint polar floor grid
const grid = new THREE.PolarGridHelper(34, 12, 8, 64, 0x14304d, 0x0d1f33);
grid.position.y = -9;
grid.material.transparent = true;
grid.material.opacity = 0.4;
scene.add(grid);

/* ---------------- starfield ---------------- */

const starGroup = new THREE.Group();
scene.add(starGroup);
{
  const N = 1100;
  const pos = new Float32Array(N * 3);
  for (let i = 0; i < N; i++) {
    const r = 45 + Math.random() * 90;
    const th = Math.random() * Math.PI * 2;
    const ph = Math.acos(2 * Math.random() - 1);
    pos[i * 3] = r * Math.sin(ph) * Math.cos(th);
    pos[i * 3 + 1] = r * Math.cos(ph) * 0.6;
    pos[i * 3 + 2] = r * Math.sin(ph) * Math.sin(th);
  }
  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
  const mat = new THREE.PointsMaterial({
    size: 0.42, color: 0x9fd8ff, transparent: true, opacity: 0.7,
    blending: THREE.AdditiveBlending, depthWrite: false, sizeAttenuation: true,
  });
  starGroup.add(new THREE.Points(geo, mat));
}

/* ---------------- shards ---------------- */

const SHARD_PALETTES = {
  shamir:   { color: 0x22d3ee, emissive: 0x0e7490, line: 0x67e8f9 },
  password: { color: 0xfbbf24, emissive: 0x92400e, line: 0xfde68a },
  none:     { color: 0x94a3b8, emissive: 0x334155, line: 0xcbd5e1 },
};

let shards = [];          // { mesh, home:Vector3, spin:Vector3, phase }
let shardMode = 'shamir';
let shaking = 0;

function ringRadius(n) { return Math.min(13, 8.2 + n * 0.24); }

function shardTarget(i, n) {
  const a = (i / n) * Math.PI * 2 + Math.PI / 7;
  const R = ringRadius(n);
  return new THREE.Vector3(
    Math.cos(a) * R,
    Math.sin(i * 2.4) * 1.6,
    Math.sin(a) * R
  );
}

function shardLabel(num, mode) {
  const c = document.createElement('canvas');
  c.width = c.height = 128;
  const g = c.getContext('2d');
  const col = mode === 'password' ? '#fbbf24' : mode === 'none' ? '#cbd5e1' : '#67e8f9';
  // hexagon
  g.beginPath();
  for (let i = 0; i < 6; i++) {
    const a = Math.PI / 6 + (i / 6) * Math.PI * 2;
    const x = 64 + Math.cos(a) * 52, y = 64 + Math.sin(a) * 52;
    i ? g.lineTo(x, y) : g.moveTo(x, y);
  }
  g.closePath();
  g.fillStyle = 'rgba(6,14,28,0.82)';
  g.fill();
  g.lineWidth = 5;
  g.strokeStyle = col;
  g.stroke();
  g.fillStyle = col;
  g.font = '700 58px Consolas, monospace';
  g.textAlign = 'center';
  g.textBaseline = 'middle';
  g.fillText(String(num), 64, 68);
  const tex = new THREE.CanvasTexture(c);
  const sprite = new THREE.Sprite(new THREE.SpriteMaterial({
    map: tex, transparent: true, opacity: 0.95, depthWrite: false,
  }));
  sprite.scale.setScalar(1.15);
  return sprite;
}

function makeShard(i, n, k, mode) {
  const pal = SHARD_PALETTES[mode] || SHARD_PALETTES.none;
  const geo = i % 2 === 0
    ? new THREE.TetrahedronGeometry(1.05 + Math.random() * 0.35)
    : new THREE.OctahedronGeometry(0.95 + Math.random() * 0.3);
  const mesh = new THREE.Mesh(geo, new THREE.MeshStandardMaterial({
    color: pal.color, emissive: pal.emissive, emissiveIntensity: 0.9,
    metalness: 0.65, roughness: 0.3, flatShading: true,
  }));

  const edges = new THREE.LineSegments(
    new THREE.EdgesGeometry(geo),
    new THREE.LineBasicMaterial({ color: pal.line, transparent: true, opacity: 0.85 })
  );
  mesh.add(edges);

  // floating part-number tag
  const label = shardLabel(i + 1, mode);
  label.position.set(0, 1.7, 0);
  mesh.add(label);

  // shards carrying a key share get a bright wire halo
  if (mode === 'shamir' && i < k) {
    const halo = new THREE.LineSegments(
      new THREE.EdgesGeometry(new THREE.OctahedronGeometry(1.7)),
      new THREE.LineBasicMaterial({ color: 0xa5f3fc, transparent: true, opacity: 0.6 })
    );
    mesh.add(halo);
    mesh.userData.keyShard = true;
  }

  mesh.userData.baseScale = 1;
  coreGroup.add(mesh);
  return mesh;
}

function clearShards() {
  for (const s of shards) {
    coreGroup.remove(s.mesh);
    s.mesh.geometry.dispose();
    s.mesh.material.dispose();
  }
  shards = [];
}

/* ---------------- micro tween engine ---------------- */

const tweens = [];
const easeOutCubic = (p) => 1 - Math.pow(1 - p, 3);
const easeInOutCubic = (p) => (p < 0.5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2);
const easeOutBack = (p) => 1 + 2.7 * Math.pow(p - 1, 3) + 1.7 * Math.pow(p - 1, 2);

function tween({ dur = 1, delay = 0, ease = easeOutCubic, update, done }) {
  tweens.push({ t: -delay, dur, ease, update, done, started: false });
}
function stepTweens(dt) {
  for (let i = tweens.length - 1; i >= 0; i--) {
    const tw = tweens[i];
    tw.t += dt;
    if (tw.t < 0) continue;
    const p = Math.min(1, tw.t / tw.dur);
    tw.update(tw.ease(p), p);
    if (p >= 1) {
      tweens.splice(i, 1);
      tw.done && tw.done();
    }
  }
}

/* ---------------- public scene actions ---------------- */

let pulseBoost = 0;

function shatter(n, k, mode = 'shamir') {
  clearShards();
  shardMode = mode;

  // core collapses
  tween({
    dur: 0.5, ease: easeInOutCubic,
    update: (e) => { coreGroup.scale.setScalar(Math.max(0.001, 1 - e)); },
  });

  // shards burst out
  for (let i = 0; i < n; i++) {
    const mesh = makeShard(i, n, k, mode);
    const target = shardTarget(i, n);
    mesh.position.set(0, 0, 0);
    mesh.scale.setScalar(0.01);

    tween({
      dur: 1.15, delay: 0.28 + i * 0.055, ease: easeOutCubic,
      update: (e) => {
        mesh.position.lerpVectors(new THREE.Vector3(), target, e);
        mesh.scale.setScalar(Math.max(0.01, e));
      },
    });

    shards.push({
      mesh,
      home: target,
      spin: new THREE.Vector3(
        (Math.random() - 0.5) * 1.6,
        (Math.random() - 0.5) * 1.6,
        (Math.random() - 0.5) * 1.6),
      phase: Math.random() * Math.PI * 2,
    });
  }
}

function assemble() {
  if (!shards.length) return;
  const n = shards.length;

  shards.forEach((s, i) => {
    const start = s.mesh.position.clone();
    tween({
      dur: 0.85, delay: i * 0.045, ease: easeInOutCubic,
      update: (e) => {
        s.mesh.position.lerpVectors(start, new THREE.Vector3(), e);
        s.mesh.scale.setScalar(Math.max(0.01, 1 - e * 0.999));
      },
      done: () => {
        coreGroup.remove(s.mesh);
        s.mesh.geometry.dispose();
      },
    });
  });
  shards = [];

  // core re-forms with a pop + flash
  tween({
    dur: 0.7, delay: 0.55, ease: easeOutBack,
    update: (e) => { coreGroup.scale.setScalar(Math.max(0.001, e)); },
  });
  pulseBoost = 1.6;
}

function fail() {
  shaking = 1;
  coreLight.color.set(0xfb7185);
  setTimeout(() => coreLight.color.set(0x38bdf8), 900);
}

function pulse() { pulseBoost = Math.max(pulseBoost, 0.9); }

/* ---------------- shard picking ---------------- */

const raycaster = new THREE.Raycaster();
const pointer = new THREE.Vector2();
let hovered = null;
let downPos = null;

canvas.addEventListener('pointermove', (e) => {
  pointer.x = (e.clientX / window.innerWidth) * 2 - 1;
  pointer.y = -(e.clientY / window.innerHeight) * 2 + 1;
});

canvas.addEventListener('pointerdown', (e) => { downPos = [e.clientX, e.clientY]; });
canvas.addEventListener('pointerup', (e) => {
  if (!downPos || hovered === null) return;
  const dx = e.clientX - downPos[0], dy = e.clientY - downPos[1];
  if (dx * dx + dy * dy < 25) {
    window.SVOnShardClick && window.SVOnShardClick(hovered.index, hovered.mesh);
  }
  downPos = null;
});

function pick() {
  if (!shards.length) { setHover(null); return; }
  raycaster.setFromCamera(pointer, camera);
  const meshes = shards.map((s) => s.mesh);
  const hit = raycaster.intersectObjects(meshes, false)[0];
  if (hit) {
    const s = shards.find((x) => x.mesh === hit.object);
    setHover(s);
  } else {
    setHover(null);
  }
}

function setHover(s) {
  if (hovered === s) return;
  if (hovered) hovered.mesh.userData.baseScale = 1;
  hovered = s || null;
  if (hovered) hovered.mesh.userData.baseScale = 1.22;
  canvas.style.cursor = hovered ? 'pointer' : (controls.enabled ? 'grab' : 'default');
}

/* ---------------- layout ---------------- */

function layout() {
  const wide = window.innerWidth >= 1024;
  const x = wide ? 6.8 : 0;
  coreGroup.position.x = x;
  grid.position.x = x;
  controls.target.set(x, 0, 0);
  camera.aspect = window.innerWidth / window.innerHeight;
  camera.updateProjectionMatrix();
  renderer.setSize(window.innerWidth, window.innerHeight);
}
window.addEventListener('resize', layout);
layout();

/* ---------------- animation loop ---------------- */

const clock = new THREE.Clock();
let mouseParallax = { x: 0, y: 0 };
window.addEventListener('pointermove', (e) => {
  mouseParallax.x = (e.clientX / window.innerWidth - 0.5);
  mouseParallax.y = (e.clientY / window.innerHeight - 0.5);
});

function animate() {
  requestAnimationFrame(animate);
  const dt = Math.min(clock.getDelta(), 0.05);
  const t = clock.elapsedTime;

  stepTweens(dt);
  pick();

  // idle motion
  if (coreGroup.scale.x > 0.5) {
    coreInner.rotation.y += dt * 0.16;
    coreInner.rotation.x += dt * 0.05;
    coreShell.rotation.y -= dt * 0.09;
    coreGroup.position.y = Math.sin(t * 0.8) * 0.35;
  }
  ring1.rotation.z += dt * 0.22;
  ring2.rotation.z -= dt * 0.15;
  starGroup.rotation.y += dt * 0.0055;
  starGroup.rotation.x = mouseParallax.y * 0.05;
  starGroup.rotation.z = -mouseParallax.x * 0.05;
  grid.rotation.y += dt * 0.02;

  // shards: tumble + float + shake
  if (shaking > 0) {
    shaking = Math.max(0, shaking - dt * 1.4);
  }
  for (const s of shards) {
    s.mesh.rotation.x += s.spin.x * dt;
    s.mesh.rotation.y += s.spin.y * dt;
    const bob = Math.sin(t * 1.3 + s.phase) * 0.22;
    const shake = shaking > 0
      ? new THREE.Vector3(
          (Math.random() - 0.5) * shaking * 0.9,
          (Math.random() - 0.5) * shaking * 0.9,
          (Math.random() - 0.5) * shaking * 0.9)
      : new THREE.Vector3();
    s.mesh.position.set(
      s.home.x + shake.x,
      s.home.y + bob + shake.y,
      s.home.z + shake.z);
    const target = s.mesh.userData.baseScale *
      (1 + Math.sin(t * 2.2 + s.phase) * 0.04);
    s.mesh.scale.setScalar(Math.max(0.01, target));
    s.mesh.material.emissiveIntensity = 0.75 +
      Math.sin(t * 2.2 + s.phase) * 0.25 +
      (s.mesh.userData.keyShard ? 0.35 : 0);
  }

  // breathing light + pulse boosts
  pulseBoost = Math.max(0, pulseBoost - dt * 1.2);
  coreLight.intensity = 26 + Math.sin(t * 2) * 5 + pulseBoost * 34;
  glow.material.opacity = 0.3 + Math.sin(t * 2) * 0.05 + pulseBoost * 0.25;
  coreInner.material.emissiveIntensity = 0.8 + pulseBoost * 1.4;
  coreShell.material.opacity = 0.45 + Math.sin(t * 2) * 0.08 + pulseBoost * 0.3;

  controls.update();
  renderer.render(scene, camera);
}
animate();

/* ---------------- public API ---------------- */

window.SVScene = { shatter, assemble, fail, pulse };
window.dispatchEvent(new Event('sv-scene-ready'));
