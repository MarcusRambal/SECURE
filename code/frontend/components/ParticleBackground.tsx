"use client";

import { useEffect, useRef } from "react";
import * as THREE from "three";
import styles from "./ParticleBackground.module.css";

export default function ParticleBackground() {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x160016);

    const camera = new THREE.PerspectiveCamera(
      60,
      window.innerWidth / window.innerHeight,
      1,
      1000,
    );
    camera.position.set(0, 0, 18);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer();
    renderer.setSize(window.innerWidth, window.innerHeight);
    container.appendChild(renderer.domElement);

    const sizes: number[] = [];
    const shifts: number[] = [];
    const points: THREE.Vector3[] = [];

    for (let i = 0; i < 100_000; i++) {
      const innerRadius = 10;
      const outerRadius = 40;
      const random = Math.pow(Math.random(), 1.5);
      const radius = Math.sqrt(
        outerRadius * outerRadius * random +
          (1 - random) * innerRadius * innerRadius,
      );
      const angle = Math.random() * Math.PI * 2;
      const depth = (Math.random() - 0.5) * 2;

      points.push(
        new THREE.Vector3(
          radius * Math.cos(angle),
          radius * Math.sin(angle),
          depth,
        ),
      );
      sizes.push(Math.random() * 1.5 + 0.5);
      shifts.push(
        Math.random() * Math.PI,
        Math.random() * Math.PI * 2,
        (Math.random() * 0.9 + 0.1) * Math.PI * 0.1,
        Math.random() * 0.9 + 0.1,
      );
    }

    const geometry = new THREE.BufferGeometry().setFromPoints(points);
    geometry.setAttribute("sizes", new THREE.Float32BufferAttribute(sizes, 1));
    geometry.setAttribute("shift", new THREE.Float32BufferAttribute(shifts, 4));

    const time = { value: 0 };
    const material = new THREE.PointsMaterial({
      size: 0.125,
      transparent: true,
      depthTest: false,
      blending: THREE.AdditiveBlending,
    });

    material.onBeforeCompile = (shader) => {
      shader.uniforms.time = time;
      shader.vertexShader = `
          uniform float time;
          attribute float sizes;
          attribute vec4 shift;
          varying vec3 vColor;
          vec3 paletteColor(float index) {
            if (index < 0.5) return vec3(251., 230., 255.);
            if (index < 1.5) return vec3(243., 184., 255.);
            if (index < 2.5) return vec3(237., 145., 255.);
            if (index < 3.5) return vec3(228., 92., 255.);
            if (index < 4.5) return vec3(220., 46., 255.);
            if (index < 5.5) return vec3(213., 0., 255.);
            if (index < 6.5) return vec3(174., 0., 209.);
            if (index < 7.5) return vec3(136., 0., 163.);
            if (index < 8.5) return vec3(98., 0., 117.);
            if (index < 9.5) return vec3(60., 0., 71.);
            return vec3(21., 0., 26.);
          }
          ${shader.vertexShader}
        `
          .replace("gl_PointSize = size;", "gl_PointSize = size * sizes;")
          .replace(
            "#include <color_vertex>",
            `#include <color_vertex>
              float palettePosition = mod((atan(position.y, position.x) + PI) / PI2, 1.0) * 11.0;
              float paletteStep = floor(palettePosition);
              float paletteBlend = fract(palettePosition);
              float currentColor = mod(paletteStep * 7.0, 11.0);
              float nextColor = mod((paletteStep + 1.0) * 7.0, 11.0);
              vColor = mix(paletteColor(currentColor), paletteColor(nextColor), paletteBlend) / 255.0;
            `,
          )
          .replace(
            "#include <begin_vertex>",
            `#include <begin_vertex>
              float t = time;
              float moveT = mod(shift.x + shift.z * t, PI2);
              float moveS = mod(shift.y + shift.z * t, PI2);
              transformed += vec3(cos(moveS) * sin(moveT), cos(moveT), sin(moveS) * sin(moveT)) * shift.a;
            `,
          );

      shader.fragmentShader = `
          varying vec3 vColor;
          ${shader.fragmentShader}
        `
          .replace(
            "#include <clipping_planes_fragment>",
            `#include <clipping_planes_fragment>
              float d = length(gl_PointCoord.xy - 0.5);
            `,
          )
          .replace(
            "vec4 diffuseColor = vec4( diffuse, opacity );",
            "vec4 diffuseColor = vec4( vColor, smoothstep(0.5, 0.1, d) );",
          );
    };

    const particles = new THREE.Points(geometry, material);
    scene.add(particles);

    const clock = new THREE.Clock();
    renderer.setAnimationLoop(() => {
      const elapsedTime = clock.getElapsedTime() * 0.5;
      time.value = elapsedTime * Math.PI;
      particles.rotation.z = elapsedTime * 0.05;
      renderer.render(scene, camera);
    });

    const handleResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    };

    window.addEventListener("resize", handleResize);

    return () => {
      window.removeEventListener("resize", handleResize);
      renderer.setAnimationLoop(null);
      scene.remove(particles);
      geometry.dispose();
      material.dispose();
      renderer.dispose();
      renderer.domElement.remove();
    };
  }, []);

  return <div ref={containerRef} className={styles.background} aria-hidden="true" />;
}
