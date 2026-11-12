"use client";

import React, { useState, useEffect } from "react";
import { HomePage } from "@/components/home-glass-view";

export default function Page() {
  const [isDark, setIsDark] = useState(true);

  useEffect(() => {
    const root = document.documentElement;
    setIsDark(root.classList.contains("dark"));
    const obs = new MutationObserver(() => {
      setIsDark(root.classList.contains("dark"));
    });
    obs.observe(root, { attributes: true, attributeFilter: ["class"] });
    return () => obs.disconnect();
  }, []);

  return (
    <HomePage
      isDark={isDark}
      onNavigateRoute={(route) => {
        if (typeof window !== "undefined") window.location.href = route;
      }}
    />
  );
}
