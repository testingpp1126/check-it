/**
 * CyberShield — 3D Globe Module (Three.js)
 * Creates an interactive, rotating Earth with threat markers and arc connections.
 */

const CyberGlobe = (() => {
    let scene, camera, renderer, globe, atmosphere, points, arcs;
    let mouseDown = false, mouseX = 0, mouseY = 0;
    let targetRotationX = 0, targetRotationY = 0;
    let autoRotateSpeed = 0.001;
    let isReady = false;
    const threatMarkers = [];
    const arcLines = [];
    const newsMarkers = [];

    // ── Convert lat/lng to 3D position ──
    function latLngToVector3(lat, lng, radius) {
        const phi = (90 - lat) * (Math.PI / 180);
        const theta = (lng + 180) * (Math.PI / 180);
        return new THREE.Vector3(
            -radius * Math.sin(phi) * Math.cos(theta),
            radius * Math.cos(phi),
            radius * Math.sin(phi) * Math.sin(theta)
        );
    }

    // ── Create custom earth wireframe ──
    function createEarth() {
        // Main sphere — wireframe style
        const geo = new THREE.SphereGeometry(5, 48, 48);
        const mat = new THREE.MeshBasicMaterial({
            color: 0x0a0a2a,
            wireframe: false,
            transparent: true,
            opacity: 0.95,
        });
        globe = new THREE.Mesh(geo, mat);

        // Wireframe overlay
        const wireGeo = new THREE.SphereGeometry(5.01, 32, 32);
        const wireMat = new THREE.MeshBasicMaterial({
            color: 0x00f0ff,
            wireframe: true,
            transparent: true,
            opacity: 0.06,
        });
        const wireframe = new THREE.Mesh(wireGeo, wireMat);
        globe.add(wireframe);

        // Latitude / longitude lines
        const linesMat = new THREE.LineBasicMaterial({ color: 0x00f0ff, transparent: true, opacity: 0.08 });
        // Latitude circles
        for (let lat = -60; lat <= 60; lat += 30) {
            const pts = [];
            for (let lng = 0; lng <= 360; lng += 5) {
                pts.push(latLngToVector3(lat, lng, 5.02));
            }
            const lineGeo = new THREE.BufferGeometry().setFromPoints(pts);
            globe.add(new THREE.Line(lineGeo, linesMat));
        }
        // Longitude lines
        for (let lng = 0; lng < 360; lng += 30) {
            const pts = [];
            for (let lat = -90; lat <= 90; lat += 5) {
                pts.push(latLngToVector3(lat, lng, 5.02));
            }
            const lineGeo = new THREE.BufferGeometry().setFromPoints(pts);
            globe.add(new THREE.Line(lineGeo, linesMat));
        }

        scene.add(globe);
    }

    // ── Create atmospheric glow ──
    function createAtmosphere() {
        const geo = new THREE.SphereGeometry(5.5, 48, 48);
        const mat = new THREE.ShaderMaterial({
            vertexShader: `
        varying vec3 vNormal;
        void main() {
          vNormal = normalize(normalMatrix * normal);
          gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
        }
      `,
            fragmentShader: `
        varying vec3 vNormal;
        void main() {
          float intensity = pow(0.65 - dot(vNormal, vec3(0.0, 0.0, 1.0)), 2.0);
          gl_FragColor = vec4(0.0, 0.94, 1.0, 1.0) * intensity * 0.5;
        }
      `,
            blending: THREE.AdditiveBlending,
            side: THREE.BackSide,
            transparent: true,
        });
        atmosphere = new THREE.Mesh(geo, mat);
        scene.add(atmosphere);
    }

    // ── Create ambient star field ──
    function createStars() {
        const starGeo = new THREE.BufferGeometry();
        const starCount = 2000;
        const positions = new Float32Array(starCount * 3);
        for (let i = 0; i < starCount * 3; i += 3) {
            const r = 50 + Math.random() * 200;
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);
            positions[i] = r * Math.sin(phi) * Math.cos(theta);
            positions[i + 1] = r * Math.sin(phi) * Math.sin(theta);
            positions[i + 2] = r * Math.cos(phi);
        }
        starGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        const starMat = new THREE.PointsMaterial({
            color: 0xffffff,
            size: 0.3,
            transparent: true,
            opacity: 0.6,
        });
        scene.add(new THREE.Points(starGeo, starMat));
    }

    // ── Add threat marker ──
    function addThreatMarker(lat, lng, severity, type) {
        const pos = latLngToVector3(lat, lng, 5.05);

        // Color by severity
        let color;
        switch (severity) {
            case 'critical': color = 0xff006e; break;
            case 'high': color = 0xff4444; break;
            case 'medium': color = 0xffaa00; break;
            default: color = 0x00ff88;
        }

        // Pulsing dot
        const dotGeo = new THREE.SphereGeometry(0.06, 8, 8);
        const dotMat = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.9 });
        const dot = new THREE.Mesh(dotGeo, dotMat);
        dot.position.copy(pos);
        dot.userData = { baseScale: 1, time: Math.random() * Math.PI * 2 };
        globe.add(dot);
        threatMarkers.push(dot);

        // Ring effect
        const ringGeo = new THREE.RingGeometry(0.08, 0.12, 16);
        const ringMat = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.4, side: THREE.DoubleSide });
        const ring = new THREE.Mesh(ringGeo, ringMat);
        ring.position.copy(pos);
        ring.lookAt(new THREE.Vector3(0, 0, 0));
        ring.userData = { time: Math.random() * Math.PI * 2 };
        globe.add(ring);
        threatMarkers.push(ring);

        // Remove old markers if too many
        while (threatMarkers.length > 200) {
            const old = threatMarkers.shift();
            globe.remove(old);
            old.geometry.dispose();
            old.material.dispose();
        }
    }

    // ── Add connection arc ──
    function addArc(srcLat, srcLng, dstLat, dstLng, severity) {
        const start = latLngToVector3(srcLat, srcLng, 5.05);
        const end = latLngToVector3(dstLat, dstLng, 5.05);

        // Mid-point elevated above globe surface
        const mid = new THREE.Vector3().addVectors(start, end).multiplyScalar(0.5);
        const dist = start.distanceTo(end);
        mid.normalize().multiplyScalar(5 + dist * 0.4);

        // Build curve
        const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
        const points = curve.getPoints(40);
        const geometry = new THREE.BufferGeometry().setFromPoints(points);

        let color;
        switch (severity) {
            case 'critical': color = 0xff006e; break;
            case 'high': color = 0xff4444; break;
            case 'medium': color = 0xffaa00; break;
            default: color = 0x00f0ff;
        }

        const material = new THREE.LineBasicMaterial({
            color,
            transparent: true,
            opacity: 0.5,
        });

        const line = new THREE.Line(geometry, material);
        line.userData = { birth: Date.now(), lifetime: 3000 + Math.random() * 2000 };
        globe.add(line);
        arcLines.push(line);

        // Cleanup old arcs
        while (arcLines.length > 30) {
            const old = arcLines.shift();
            globe.remove(old);
            old.geometry.dispose();
            old.material.dispose();
        }
    }

    // ── Add news marker (distinct style) ──
    function addNewsMarker(lat, lng, title, url) {
        const pos = latLngToVector3(lat, lng, 5.08);
        const color = 0xff66cc;

        const geo = new THREE.SphereGeometry(0.045, 8, 8);
        const mat = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.95 });
        const node = new THREE.Mesh(geo, mat);
        node.position.copy(pos);
        node.userData = { title, url, time: Math.random() * Math.PI * 2 };
        globe.add(node);
        newsMarkers.push(node);

        // cleanup if too many
        while (newsMarkers.length > 200) {
            const old = newsMarkers.shift();
            globe.remove(old);
            old.geometry.dispose();
            old.material.dispose();
        }
    }

    function clearNewsMarkers() {
        while (newsMarkers.length) {
            const m = newsMarkers.shift();
            globe.remove(m);
            try { m.geometry.dispose(); m.material.dispose(); } catch (e) {}
        }
    }

    // ── Rotate/zoom globe to focus on lat/lng (animated via targetRotation)
    function focusOn(lat, lng) {
        // longitude -> rotation.y (negated to bring point to front)
        const theta = (lng) * (Math.PI / 180);
        const phi = (lat) * (Math.PI / 180);
        targetRotationY = -theta;
        // tilt a bit based on latitude
        targetRotationX = Math.max(-Math.PI / 3, Math.min(Math.PI / 3, phi * 0.6));
    }

    // ── Handle resize ──
    function onResize() {
        const container = document.getElementById('globe-container');
        if (!container || !renderer) return;
        const w = container.clientWidth;
        const h = container.clientHeight;
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
        renderer.setSize(w, h);
    }

    // ── Mouse interaction ──
    function onMouseDown(e) {
        mouseDown = true;
        mouseX = e.clientX;
        mouseY = e.clientY;
    }

    function onMouseMove(e) {
        if (!mouseDown) return;
        const dx = e.clientX - mouseX;
        const dy = e.clientY - mouseY;
        targetRotationY += dx * 0.005;
        targetRotationX += dy * 0.005;
        mouseX = e.clientX;
        mouseY = e.clientY;
    }

    function onMouseUp() {
        mouseDown = false;
    }

    // ── Touch support ──
    function onTouchStart(e) {
        if (e.touches.length === 1) {
            mouseDown = true;
            mouseX = e.touches[0].clientX;
            mouseY = e.touches[0].clientY;
        }
    }

    function onTouchMove(e) {
        if (!mouseDown || e.touches.length !== 1) return;
        e.preventDefault();
        const dx = e.touches[0].clientX - mouseX;
        const dy = e.touches[0].clientY - mouseY;
        targetRotationY += dx * 0.005;
        targetRotationX += dy * 0.005;
        mouseX = e.touches[0].clientX;
        mouseY = e.touches[0].clientY;
    }

    // ── Animate ──
    function animate() {
        requestAnimationFrame(animate);

        if (globe) {
            // Auto-rotate
            if (!mouseDown) {
                targetRotationY += autoRotateSpeed;
            }

            globe.rotation.y += (targetRotationY - globe.rotation.y) * 0.05;
            globe.rotation.x += (targetRotationX - globe.rotation.x) * 0.05;

            // Clamp vertical rotation
            globe.rotation.x = Math.max(-Math.PI / 3, Math.min(Math.PI / 3, globe.rotation.x));

            // Pulse threat markers
            const time = Date.now() * 0.003;
            threatMarkers.forEach(marker => {
                if (marker.userData.time !== undefined) {
                    const scale = 1 + Math.sin(time + marker.userData.time) * 0.3;
                    marker.scale.set(scale, scale, scale);
                }
            });

            // subtle pulse for news markers
            newsMarkers.forEach(marker => {
                if (marker.userData.time !== undefined) {
                    const s = 1 + Math.sin(time + marker.userData.time) * 0.18;
                    marker.scale.set(s, s, s);
                }
            });

            // Fade out old arcs
            const now = Date.now();
            for (let i = arcLines.length - 1; i >= 0; i--) {
                const arc = arcLines[i];
                const age = now - arc.userData.birth;
                const life = arc.userData.lifetime;
                if (age > life) {
                    globe.remove(arc);
                    arc.geometry.dispose();
                    arc.material.dispose();
                    arcLines.splice(i, 1);
                } else {
                    arc.material.opacity = Math.max(0, 0.5 * (1 - age / life));
                }
            }
        }

        renderer.render(scene, camera);
    }

    // ── Init ──
    function init() {
        const container = document.getElementById('globe-container');
        const canvas = document.getElementById('globe-canvas');
        if (!container || !canvas) return;

        const w = container.clientWidth;
        const h = container.clientHeight;

        scene = new THREE.Scene();
        camera = new THREE.PerspectiveCamera(45, w / h, 0.1, 1000);
        camera.position.z = 15;

        renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
        renderer.setSize(w, h);
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

        createEarth();
        createAtmosphere();
        createStars();

        // Ambient light
        scene.add(new THREE.AmbientLight(0x404040, 0.5));

        // Event listeners
        canvas.addEventListener('mousedown', onMouseDown);
        window.addEventListener('mousemove', onMouseMove);
        window.addEventListener('mouseup', onMouseUp);
        canvas.addEventListener('touchstart', onTouchStart, { passive: false });
        canvas.addEventListener('touchmove', onTouchMove, { passive: false });
        canvas.addEventListener('touchend', onMouseUp);
        window.addEventListener('resize', onResize);

        animate();
        isReady = true;

        // notify listeners that the globe is ready
        try {
            window.dispatchEvent(new CustomEvent('cyberglobe:ready'));
        } catch (e) {}

        // Hide loading overlay
        setTimeout(() => {
            const overlay = document.getElementById('globe-overlay');
            if (overlay) overlay.classList.add('hidden');
        }, 800);
    }

    return {
        init,
        addThreatMarker,
        addArc,
        addNewsMarker,
        clearNewsMarkers,
        focusOn,
        get isReady() { return isReady; },
    };
})();
