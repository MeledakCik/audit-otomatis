"use client";

import { useCallback, useRef, useState } from "react";
import { UploadCloud, FileCode2, Loader2, ScanSearch, X } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { detectInputKind } from "@/lib/maintenance/analyzer";
import { cn } from "@/lib/utils";

const MAX_FILE_MB = 10;
const ACCEPTED_EXT = [".json", ".log", ".txt", ".har"];

const INPUT_KIND_LABEL: Record<string, string> = {
  "npm-audit-json": "npm audit JSON",
  "next-build-log": "Next.js build log",
  "access-log": "Access log",
  "cloudflare-log": "Cloudflare log",
  har: "HAR file",
  "source-code": "Source code",
  "stack-trace": "Stack trace",
  unknown: "Tidak dikenali (akan dicoba sebagai code)",
};

interface InputPanelProps {
  onAnalyze: (input: string, filename?: string) => void;
  loading: boolean;
}

export function InputPanel({ onAnalyze, loading }: InputPanelProps) {
  const [mode, setMode] = useState<"upload" | "paste">("upload");
  const [file, setFile] = useState<{ name: string; content: string } | null>(null);
  const [pasted, setPasted] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback((f: File) => {
    setError(null);
    const ext = "." + f.name.split(".").pop()?.toLowerCase();
    if (!ACCEPTED_EXT.includes(ext)) {
      setError(`Tipe file tidak didukung. Gunakan: ${ACCEPTED_EXT.join(", ")}`);
      return;
    }
    if (f.size > MAX_FILE_MB * 1024 * 1024) {
      setError(`File terlalu besar (maks. ${MAX_FILE_MB}MB).`);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setFile({ name: f.name, content: String(reader.result ?? "") });
    };
    reader.onerror = () => setError("Gagal membaca file.");
    reader.readAsText(f);
  }, []);

  const activeInput = mode === "upload" ? file?.content ?? "" : pasted;
  const activeFilename = mode === "upload" ? file?.name : undefined;
  const detectedKind = activeInput.trim() ? detectInputKind(activeInput, activeFilename) : null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <ScanSearch className="h-3.5 w-3.5 text-accent" />
          Input Analisis
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Tabs value={mode} onValueChange={(v) => setMode(v as "upload" | "paste")}>
          <TabsList>
            <TabsTrigger value="upload">
              <UploadCloud className="h-3.5 w-3.5" /> Upload File
            </TabsTrigger>
            <TabsTrigger value="paste">
              <FileCode2 className="h-3.5 w-3.5" /> Paste Code / Log
            </TabsTrigger>
          </TabsList>

          <TabsContent value="upload">
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragOver(false);
                const f = e.dataTransfer.files?.[0];
                if (f) handleFile(f);
              }}
              onClick={() => fileInputRef.current?.click()}
              className={cn(
                "flex flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed px-6 py-10 text-center cursor-pointer transition-colors",
                dragOver ? "border-accent bg-accent/10" : "border-border-strong hover:border-accent/60"
              )}
            >
              <UploadCloud className="h-8 w-8 text-muted-dim" />
              <div className="text-sm font-medium text-foreground">
                Drag & drop file, atau klik untuk pilih
              </div>
              <div className="text-[11px] font-mono text-muted-dim">
                .json · .log · .txt · .har — maks. {MAX_FILE_MB}MB
              </div>
              <div className="text-[10px] font-mono text-muted-dim/70 pt-1">
                Contoh: npm audit --json, next build log, vercel log, access.log, error stack trace
              </div>
              <input
                ref={fileInputRef}
                type="file"
                accept={ACCEPTED_EXT.join(",")}
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) handleFile(f);
                }}
              />
            </div>

            {file && (
              <div className="mt-3 flex items-center justify-between rounded-lg border border-border bg-surface-raised px-3 py-2">
                <div className="flex items-center gap-2 text-xs font-mono text-foreground truncate">
                  <FileCode2 className="h-3.5 w-3.5 text-accent shrink-0" />
                  <span className="truncate">{file.name}</span>
                  <span className="text-muted-dim">({(file.content.length / 1024).toFixed(1)} KB)</span>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setFile(null);
                  }}
                  className="text-muted-dim hover:text-sev-critical transition-colors shrink-0"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            )}
          </TabsContent>

          <TabsContent value="paste">
            <textarea
              value={pasted}
              onChange={(e) => setPasted(e.target.value)}
              placeholder={`Paste JS / PHP / Python / Next.js build log / Nginx log / Cloudflare log di sini...\n\nContoh:\nconst el = document.getElementById("x");\nel.innerHTML = userInput;`}
              spellCheck={false}
              className={cn(
                "w-full h-64 resize-y rounded-xl border border-border bg-[#0a0710] text-[#d6d0e8] font-mono text-[12.5px] leading-relaxed p-4",
                "focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent placeholder:text-muted-dim/60"
              )}
            />
          </TabsContent>
        </Tabs>

        {error && <div className="text-xs font-mono text-sev-critical">{error}</div>}

        {detectedKind && (
          <div className="flex items-center gap-2 text-[11px] font-mono text-muted">
            <span className="text-muted-dim uppercase tracking-wider">Auto-detect:</span>
            <span className="text-accent font-semibold">{INPUT_KIND_LABEL[detectedKind]}</span>
          </div>
        )}

        <Button
          className="w-full"
          disabled={!activeInput.trim() || loading}
          onClick={() => onAnalyze(activeInput, activeFilename)}
        >
          {loading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" /> Menganalisis...
            </>
          ) : (
            <>
              <ScanSearch className="h-4 w-4" /> Analyze with Sentinel AI
            </>
          )}
        </Button>
      </CardContent>
    </Card>
  );
}
