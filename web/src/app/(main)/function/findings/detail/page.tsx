"use client";

import * as React from "react";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { ArrowLeftIcon, ArrowUpRightIcon, ChevronLeftIcon, ChevronRightIcon, FileDownIcon, ShieldAlertIcon } from "lucide-react";
import { Spinner } from "@/components/ui/spinner";
import { toast } from "sonner";

import { CopyButton } from "@/components/copy-button";
import { FindingRetestPanel } from "@/components/finding-retest-panel";
import { ArtifactDataViewerDialog } from "@/components/artifact-data-viewer";
import { ZoomableImageDialog } from "@/components/zoomable-image-dialog";
import { FindingTrafficPanel } from "@/components/finding-traffic-panel";
import { EvidenceView } from "@/components/evidence-view";
import { Markdown } from "@/components/markdown";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { statusMeta } from "@/lib/status";
import type { Finding, FindingStatus, Severity, TaskArtifact } from "@/lib/types";

import { FindingLineageView } from "./lineage";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const FINDING_STATUSES: FindingStatus[] = [
  "pending",
  "in_progress",
  "confirmed",
  "resolved",
  "fixed",
  "false_positive",
  "ignored",
  "duplicate",
  "risk_accepted",
];

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString("zh-CN");
}

// FieldRow is one label/value line in the right-hand status panel.
function FieldRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-2.5">
      <span className="shrink-0 pt-0.5 text-muted-foreground text-xs">{label}</span>
      <div className="flex min-w-0 flex-col items-end gap-1 text-right text-sm">{children}</div>
    </div>
  );
}

function FindingDetailInner() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") ?? "";
  const contextTaskId = searchParams.get("context_task") ?? "";
  const [exporting, setExporting] = React.useState(false);
  const [finding, setFinding] = React.useState<Finding | null>(null);
  const [loaded, setLoaded] = React.useState(false);
  const [tab, setTab] = React.useState("overview");

  const load = React.useCallback(() => {
    if (!id) {
      setLoaded(true);
      return;
    }
    api
      .getFinding(id, contextTaskId || undefined)
      .then((f) => setFinding(f))
      .catch(() => setFinding(null))
      .finally(() => setLoaded(true));
  }, [contextTaskId, id]);
  React.useEffect(() => {
    load();
  }, [load]);

  const changeSeverity = React.useCallback(
    async (next: Severity) => {
      if (!finding || finding.inherited || next === finding.severity) return;
      const prev = finding.severity;
      setFinding({ ...finding, severity: next });
      try {
        const updated = await api.setFindingSeverity(id, next);
        setFinding(updated);
        toast.success(`严重等级已改为「${statusMeta("severity", next).label}」`);
      } catch (e) {
        setFinding((cur) => (cur ? { ...cur, severity: prev } : cur));
        toast.error(`更新失败：${(e as Error).message}`);
      }
    },
    [finding, id],
  );

  const changeStatus = React.useCallback(
    async (next: FindingStatus) => {
      if (!finding || finding.inherited || next === finding.status) return;
      const prev = finding.status;
      setFinding({ ...finding, status: next });
      try {
        const updated = await api.setFindingStatus(id, next);
        setFinding(updated);
        toast.success(`处理状态已改为「${statusMeta("finding", next).label}」`);
      } catch (e) {
        setFinding((cur) => (cur ? { ...cur, status: prev } : cur));
        toast.error(`更新失败：${(e as Error).message}`);
      }
    },
    [finding, id],
  );

  if (!finding) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-10 text-center">
        <p className="text-muted-foreground">{loaded ? `未找到发现 ${id}` : "加载中…"}</p>
        {loaded && (
          <Button asChild variant="outline">
            <Link href="/function/findings">
              <ArrowLeftIcon /> 返回发现列表
            </Link>
          </Button>
        )}
      </div>
    );
  }

  const title = finding.name || finding.vulnclass || "未分类";

  return (
    <Tabs value={tab} onValueChange={setTab} className="flex flex-1 flex-col gap-0">
      {/* Sticky header */}
      <header className="sticky top-0 z-10 flex flex-col gap-2 border-b bg-background/95 px-4 py-2.5 backdrop-blur lg:px-6">
        <div className="flex flex-wrap items-center gap-2">
          <SidebarTrigger className="-ml-1" />
          <Button asChild variant="ghost" size="icon" className="size-7">
            <Link href="/function/findings">
              <ArrowLeftIcon />
            </Link>
          </Button>
          <ShieldAlertIcon className="size-4 text-muted-foreground" />
          <h1 className="max-w-md truncate font-semibold text-sm" title={title}>
            {title}
          </h1>
          <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-muted-foreground text-xs">#{finding.id}</code>
          <Separator orientation="vertical" className="mx-1 h-4" />
          <Button
            size="sm"
            variant="outline"
            disabled={exporting}
            onClick={async () => {
              setExporting(true);
              try {
                await api.downloadFindingDocx(finding.id);
                toast.success("Word 已开始下载（含证据附件，文件较大请稍候）");
              } catch (e) {
                toast.error(`导出失败：${(e as Error).message}`);
              } finally {
                setExporting(false);
              }
            }}
          >
            {exporting ? <Spinner data-icon="inline-start" /> : <FileDownIcon />} {exporting ? "导出中…" : "导出 Word"}
          </Button>
          <StatusBadge domain="severity" value={finding.severity} dot />
          <StatusBadge domain="finding" value={finding.status} dot />
          {finding.inherited && finding.source_task_id && (
            <Badge variant="outline">来源任务 #{finding.source_task_id} · 只读</Badge>
          )}
        </div>
        <TabsList>
          <TabsTrigger value="overview">概览</TabsTrigger>
          <TabsTrigger value="lineage">链路图</TabsTrigger>
        </TabsList>
      </header>

      {/* Tab content */}
      <div className="flex-1 p-4 lg:p-6">
        {/* 概览：左（摘要 + 证据）/ 右（状态区） */}
        <TabsContent value="overview" className="mt-0">
          <div className="grid gap-4 lg:grid-cols-3">
            {/* 左栏 */}
            <div className="flex flex-col gap-4 lg:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">摘要</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="whitespace-pre-wrap text-sm leading-relaxed">{finding.summary || "（无摘要）"}</p>
                </CardContent>
              </Card>
              {/* 现场截图（v0.4.9）：关键照片在详情页直接可见，不用翻 Word。
                  只展示 finding_id 归属本漏洞的图片附件。 */}
              <FindingShots
                taskId={finding.task_id ? String(finding.task_id) : contextTaskId}
                findingId={String(id)}
              />
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">证据 / PoC</CardTitle>
                </CardHeader>
                <CardContent>
                  {finding.evidence ? (
                    <EvidenceView text={finding.evidence} className="max-h-[60vh] overflow-y-auto pr-1" />
                  ) : (
                    <p className="text-muted-foreground text-sm">（无证据）</p>
                  )}
                </CardContent>
              </Card>
              {/* 证据下方：详细报告(Markdown 渲染) */}
              <Card>
                <CardHeader className="flex-row items-center justify-between">
                  <CardTitle className="text-sm">详细报告</CardTitle>
                  {finding.report && <CopyButton text={finding.report} successMessage="已复制详细报告" />}
                </CardHeader>
                <CardContent>
                  {finding.report_stale ? (
                    <Alert>
                      <AlertDescription>流量证据已变更，详细报告待更新。</AlertDescription>
                    </Alert>
                  ) : null}
                  {finding.report ? (
                    <Markdown text={finding.report} />
                  ) : (
                    <p className="text-muted-foreground text-sm">暂无详细报告。</p>
                  )}
                </CardContent>
              </Card>
              {/* 关联流量放在报告之后（v0.4.9）：先看结论与叙事，再下钻原始报文；
                  v0.4.11 起默认折叠——要看时点「查看详细流量」，不占阅读篇幅。 */}
              <FindingTrafficPanel
                key={id}
                findingId={id}
                contextTask={contextTaskId || undefined}
                readOnly={finding.inherited}
                onChanged={load}
              />
              {/* 复测记录放最后：属于验证后的后续动作。 */}
              <FindingRetestPanel key={`retest-${id}`} findingId={id} readOnly={finding.inherited} onCompleted={load} />
            </div>

            {/* 右栏：状态区 */}
            <Card className="h-fit lg:sticky lg:top-24">
              <CardHeader>
                <CardTitle className="text-sm">状态</CardTitle>
              </CardHeader>
              <CardContent className="divide-y">
                {/* 漏洞 ID */}
                <FieldRow label="漏洞 ID">
                  <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-muted-foreground text-xs">
                    #{finding.id}
                  </code>
                </FieldRow>

                {/* 严重等级 */}
                <FieldRow label="严重等级">
                  {finding.inherited ? (
                    <StatusBadge domain="severity" value={finding.severity} dot />
                  ) : (
                    <Select value={finding.severity} onValueChange={(v) => changeSeverity(v as Severity)}>
                      <SelectTrigger size="sm" className="h-7 w-auto border-none px-1 shadow-none focus-visible:ring-0">
                        <StatusBadge domain="severity" value={finding.severity} dot />
                      </SelectTrigger>
                      <SelectContent position="popper" align="end">
                        <SelectGroup>
                          {SEVERITIES.map((sv) => (
                            <SelectItem key={sv} value={sv}>
                              {statusMeta("severity", sv).label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  )}
                </FieldRow>

                {/* 处理状态 */}
                <FieldRow label="处理状态">
                  {finding.inherited ? (
                    <StatusBadge domain="finding" value={finding.status} dot />
                  ) : (
                    <Select value={finding.status} onValueChange={(v) => changeStatus(v as FindingStatus)}>
                      <SelectTrigger size="sm" className="h-7 w-auto border-none px-1 shadow-none focus-visible:ring-0">
                        <StatusBadge domain="finding" value={finding.status} dot />
                      </SelectTrigger>
                      <SelectContent position="popper" align="end">
                        <SelectGroup>
                          {FINDING_STATUSES.map((st) => (
                            <SelectItem key={st} value={st}>
                              {statusMeta("finding", st).label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  )}
                </FieldRow>

                {/* 漏洞类型 */}
                <FieldRow label="漏洞类型">
                  {finding.vulnclass ? (
                    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{finding.vulnclass}</code>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </FieldRow>

                {/* 涉及资产 */}
                <FieldRow label="涉及资产">
                  {finding.assets && finding.assets.length > 0 ? (
                    <div className="flex flex-wrap justify-end gap-1">
                      {finding.assets.map((a) => (
                        <code
                          key={a.id}
                          className="max-w-[16rem] truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                          title={`${a.type} · ${a.label}`}
                        >
                          {a.label}
                        </code>
                      ))}
                    </div>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </FieldRow>

                {/* 所属任务 */}
                <FieldRow label="所属任务">
                  {finding.task_id ? (
                    <Link
                      href={`/function/tasks/detail?id=${finding.task_id}`}
                      className="inline-flex max-w-[16rem] items-center gap-1 text-primary hover:underline"
                      title={finding.task_description}
                    >
                      <span className="truncate">{finding.task_description || `#${finding.task_id}`}</span>
                      <ArrowUpRightIcon className="size-3 shrink-0" />
                    </Link>
                  ) : (
                    <span className="text-muted-foreground">—（任务已删除）</span>
                  )}
                </FieldRow>

                {/* 发现时间 */}
                <FieldRow label="发现时间">
                  <span className="tabular-nums">{fmtTime(finding.ts)}</span>
                </FieldRow>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* 链路图：从任务初始节点回溯到本漏洞节点的攻击链路 */}
        <TabsContent value="lineage" className="mt-0">
          <FindingLineageView findingId={finding.id} />
        </TabsContent>
      </div>
    </Tabs>
  );
}

// useSearchParams must sit under a Suspense boundary for static export.
export default function FindingDetailPage() {
  return (
    <React.Suspense fallback={null}>
      <FindingDetailInner />
    </React.Suspense>
  );
}


// FindingShots 漏洞现场截图（v0.4.9 起；v0.4.15 交互重做）：默认折叠，
// 缩略图走服务端缩略图（原图太大，一次加载几十张会破图），悬停放大、
// 点击弹层看细节；下载在弹层里单独给按钮。
function FindingShots({ taskId, findingId }: { taskId?: string; findingId: string }) {
  const [all, setAll] = React.useState<TaskArtifact[]>([]);
  const [expanded, setExpanded] = React.useState(false);
  const [preview, setPreview] = React.useState<TaskArtifact | null>(null);
  const [docPreview, setDocPreview] = React.useState<{ artifact: TaskArtifact; page: number } | null>(null);
  const [broken, setBroken] = React.useState<Record<number, boolean>>({});
  const [pickerOpen, setPickerOpen] = React.useState(false);
  const [pickSelected, setPickSelected] = React.useState<number[]>([]);
  const [picking, setPicking] = React.useState(false);
  const load = React.useCallback(() => {
    if (!taskId) return;
    api
      .taskArtifacts(taskId)
      .then(setAll)
      .catch(() => {});
  }, [taskId]);
  React.useEffect(() => {
    load();
  }, [load]);
  // 归属本漏洞的图片与文档（v0.4.24）：任务级证据仍只在任务总览里看。
  const isDoc = (a: TaskArtifact) =>
    ["document", "spreadsheet", "presentation", "pdf"].includes(a.kind) ||
    /\.(docx?|xlsx?|pptx?|pdf|odt|ods|odp|csv|rtf)$/i.test(a.name);
  const own = all.filter(
    (a) => String(a.finding_id ?? "") === findingId && (a.kind === "image" || isDoc(a)),
  );
  const [dataPreview, setDataPreview] = React.useState<TaskArtifact | null>(null);
  const dataOwn = own.filter((a) => a.kind === "data" || a.kind === "log");
  const images = own.filter((a) => a.kind === "image");
  const docs = own.filter((a) => a.kind !== "image" && isDoc(a));
  // 本漏洞已归属但不是可视证据的附件（JSON/日志/HTML），空态时要说清楚，
  // 避免用户误以为“这个漏洞什么都没留下”。
  const otherOwn = all.filter(
    (a) => String(a.finding_id ?? "") === findingId && a.kind !== "image" && !isDoc(a),
  );
  // 可供挑选的任务级证据（未归属的图片/文档）。
  const candidates = all.filter((a) => !a.finding_id && (a.kind === "image" || isDoc(a)));
  const thumbUrl = (id: number) => `${api.artifactUrl(taskId!, id)}?thumb=1`;
  const fullUrl = (id: number) => api.artifactUrl(taskId!, id);
  const downloadUrl = (id: number) => `${api.artifactUrl(taskId!, id)}?download=1`;
  const previewUrl = (id: number, page: number) => api.artifactPreviewUrl(taskId!, id, page);
  const docLabel = (a: TaskArtifact) => {
    const ext = (a.name.split(".").pop() || "").toLowerCase();
    if (["doc", "docx", "odt", "rtf"].includes(ext) || a.kind === "document") return "Word";
    if (["xls", "xlsx", "ods", "csv"].includes(ext) || a.kind === "spreadsheet") return "Excel/CSV";
    if (["ppt", "pptx", "odp"].includes(ext) || a.kind === "presentation") return "PPT";
    if (ext === "pdf" || a.kind === "pdf") return "PDF";
    return a.kind;
  };
  const regeneratePreview = async (a: TaskArtifact) => {
    if (!taskId) return;
    try {
      await api.regenerateArtifactPreview(taskId, a.id);
      window.setTimeout(load, 1500);
    } catch (e) {
      toast.error((e as Error).message);
    }
  };
  const applyPick = async () => {
    if (!taskId || pickSelected.length === 0) return;
    setPicking(true);
    try {
      for (const id of pickSelected) {
        await api.updateTaskArtifact(taskId, id, Number(findingId));
      }
      toast.success(`已把 ${pickSelected.length} 项证据归属到本漏洞`);
      setPickSelected([]);
      setPickerOpen(false);
      load();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setPicking(false);
    }
  };
  React.useEffect(() => {
    if (!expanded || !own.some((a) => a.preview_state === "pending")) return;
    const t = window.setInterval(load, 4000);
    return () => window.clearInterval(t);
  }, [expanded, own, load]);
  const pickerDialog = (
    <Dialog open={pickerOpen} onOpenChange={setPickerOpen}>
      <DialogContent className="max-w-5xl">
        <DialogHeader>
          <DialogTitle className="text-base">从任务证据中挑选（归属到本漏洞）</DialogTitle>
        </DialogHeader>
        {candidates.length === 0 ? (
          <p className="text-muted-foreground text-sm">
            任务里没有未归属的图片或文档。到任务总览「证据附件」可以先把其他漏洞的图改回任务级，或等待 worker 继续取证。
          </p>
        ) : (
          <>
            <div className="grid max-h-[60vh] grid-cols-2 gap-2 overflow-y-auto pr-1 sm:grid-cols-3 lg:grid-cols-5">
              {candidates.map((a) => {
                const checked = pickSelected.includes(a.id);
                return (
                  <label
                    key={a.id}
                    className={`relative flex cursor-pointer flex-col overflow-hidden rounded-md border text-left ${
                      checked ? "ring-2 ring-primary" : ""
                    }`}
                  >
                    <input
                      type="checkbox"
                      className="absolute top-1.5 left-1.5 z-10 size-4 accent-primary"
                      checked={checked}
                      onChange={() =>
                        setPickSelected((cur) =>
                          cur.includes(a.id) ? cur.filter((x) => x !== a.id) : [...cur, a.id],
                        )
                      }
                    />
                    <span className="flex aspect-[4/3] items-center justify-center bg-muted/40">
                      {a.kind === "image" ? (
                        // eslint-disable-next-line @next/next/no-img-element
                        <img src={thumbUrl(a.id)} alt={a.note || a.name} loading="lazy" className="h-full w-full object-cover" />
                      ) : a.preview_state === "ready" ? (
                        // eslint-disable-next-line @next/next/no-img-element
                        <img
                          src={previewUrl(a.id, 1)}
                          alt={a.note || a.name}
                          loading="lazy"
                          className="h-full w-full object-cover object-top"
                        />
                      ) : (
                        <span className="p-2 text-center text-[11px] text-muted-foreground">
                          {a.preview_state === "pending" ? "预览生成中…" : "暂无预览"}
                        </span>
                      )}
                    </span>
                    <span className="line-clamp-2 bg-background/90 px-1.5 py-1 text-[10px]">
                      {a.kind === "image" ? "" : `${docLabel(a)} · `}
                      {a.name}
                    </span>
                  </label>
                );
              })}
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-muted-foreground text-xs">已选 {pickSelected.length} 项</span>
              <div className="flex gap-2">
                <Button size="sm" variant="ghost" onClick={() => setPickSelected([])}>
                  清空
                </Button>
                <Button size="sm" disabled={picking || pickSelected.length === 0} onClick={() => void applyPick()}>
                  {picking ? "保存中…" : "归属到本漏洞"}
                </Button>
              </div>
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
  if (!taskId) return null;
  if (own.length === 0) {
    return (
      <>
        <Card>
          <CardContent className="flex flex-wrap items-center justify-between gap-3 py-4 text-sm text-muted-foreground">
            <span>
              {otherOwn.length > 0
                ? `本漏洞有 ${otherOwn.length} 个数据/日志附件，但没有可预览的图片或文档。`
                : "本漏洞暂无专属截图或文档。"}
              任务级证据（目标首页、批次照片等）请到任务总览的「证据附件」查看，也可以直接从任务证据里挑选后归属到本漏洞。
            </span>
            <div className="flex items-center gap-2">
              {dataOwn.length > 0 ? (
                <Button size="sm" variant="default" onClick={() => setDataPreview(dataOwn[0])}>
                  查看数据（{dataOwn.length}）
                </Button>
              ) : (
                <Button
                  size="sm"
                  variant="default"
                  onClick={() => {
                    setPickSelected([]);
                    setPickerOpen(true);
                  }}
                >
                  从任务证据中挑选
                </Button>
              )}
              <Button size="sm" variant="outline" asChild>
                <Link href={`/function/tasks/detail?id=${taskId}&tab=overview`}>
                  查看任务总览 <ArrowUpRightIcon className="size-3.5" />
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
        {pickerDialog}
      </>
    );
  }
  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            现场证据（{own.length}）
            <span className="font-normal text-muted-foreground text-xs">
              {" "}
              · 仅显示归属本漏洞的图片与文档（图片 {images.length} / 文档 {docs.length}）
            </span>
            <Button
              size="sm"
              variant="ghost"
              className="ml-auto"
              onClick={() => {
                setPickSelected([]);
                setPickerOpen(true);
              }}
            >
              添加证据
            </Button>
            <Button size="sm" variant="outline" onClick={() => setExpanded((v) => !v)}>
              {expanded ? "收起" : "展开查看"}
            </Button>
          </CardTitle>
        </CardHeader>

        {dataOwn.length > 0 && (
          <CardContent className="flex flex-col gap-2 border-t pt-4">
            <div className="text-muted-foreground text-xs">
              数据证据（{dataOwn.length}）：点「查看数据」在线阅读（JSON/CSV 转表格），或下载原件。
            </div>
            <div className="flex flex-col divide-y rounded border">
              {dataOwn.map((a) => (
                <div key={a.id} className="flex min-w-0 items-center gap-2 px-3 py-2 text-sm">
                  <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-muted-foreground text-xs">数据</span>
                  <span className="min-w-0 flex-1 truncate" title={a.note || a.name}>{a.name}</span>
                  <span className="shrink-0 text-muted-foreground text-xs">{(a.size_bytes / 1024).toFixed(0)}KB</span>
                  <Button size="sm" variant="outline" onClick={() => setDataPreview(a)}>
                    查看数据
                  </Button>
                  <Button size="sm" variant="ghost" asChild>
                    <a href={`${api.artifactUrl(taskId!, a.id)}?download=1`}>下载</a>
                  </Button>
                </div>
              ))}
            </div>
          </CardContent>
        )}
        {expanded && (
          <CardContent className="flex flex-col gap-3">
            {images.length > 0 && (
              <div className="grid grid-cols-3 gap-2 sm:grid-cols-4 lg:grid-cols-6">
                {images.map((a) => (
                  <button
                    key={a.id}
                    type="button"
                    onClick={() => setPreview(a)}
                    className="group relative aspect-square overflow-hidden rounded-md border bg-muted/40 text-left"
                    title={a.note || a.name}
                  >
                    {broken[a.id] ? (
                      <span className="flex h-full w-full flex-col items-center justify-center gap-1 p-2 text-center text-[11px] text-muted-foreground">
                        无法预览
                        <span className="line-clamp-2 break-all">{a.name}</span>
                      </span>
                    ) : (
                      // eslint-disable-next-line @next/next/no-img-element
                      <img
                        src={thumbUrl(a.id)}
                        alt={a.note || a.name}
                        loading="lazy"
                        onError={() => setBroken((b) => ({ ...b, [a.id]: true }))}
                        className="h-full w-full object-cover transition-transform duration-200 group-hover:scale-105"
                      />
                    )}
                    <span className="pointer-events-none absolute inset-x-0 bottom-0 line-clamp-1 bg-black/55 px-1.5 py-0.5 text-[10px] text-white">
                      {a.note || a.name}
                    </span>
                  </button>
                ))}
              </div>
            )}
            {docs.length > 0 && (
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
                {docs.map((a) => {
                  const ready = a.preview_state === "ready" && (a.preview_pages ?? 0) > 0;
                  const stateText =
                    a.preview_state === "pending"
                      ? "预览生成中…"
                      : a.preview_state === "failed"
                        ? "预览失败"
                        : a.preview_state === "skipped"
                          ? "未生成预览"
                          : "点击生成预览";
                  return (
                    <button
                      key={a.id}
                      type="button"
                      onClick={() => (ready ? setDocPreview({ artifact: a, page: 1 }) : void regeneratePreview(a))}
                      className="group relative flex aspect-[4/3] w-full flex-col overflow-hidden rounded-md border bg-muted/40 text-left"
                      title={a.preview_error || a.note || a.name}
                    >
                      {ready ? (
                        // eslint-disable-next-line @next/next/no-img-element
                        <img
                          src={previewUrl(a.id, 1)}
                          alt={a.note || a.name}
                          loading="lazy"
                          className="h-full w-full object-cover object-top transition-transform duration-200 group-hover:scale-105"
                        />
                      ) : (
                        <span className="flex h-full w-full flex-col items-center justify-center gap-1 p-3 text-center text-[11px] text-muted-foreground">
                          <FileDownIcon className="size-5" />
                          {stateText}
                          {a.preview_error ? <span className="line-clamp-2 break-all">{a.preview_error}</span> : null}
                        </span>
                      )}
                      <span className="pointer-events-none absolute inset-x-0 bottom-0 bg-black/60 px-1.5 py-0.5 text-[10px] text-white">
                        {docLabel(a)}
                        {ready ? ` · ${a.preview_pages} 页` : ""} · {a.name}
                      </span>
                    </button>
                  );
                })}
              </div>
            )}
          </CardContent>
        )}
      </Card>
      <ZoomableImageDialog
        open={!!preview}
        onClose={() => setPreview(null)}
        src={preview ? fullUrl(preview.id) : ""}
        title={preview?.note || preview?.name || ""}
        description={preview ? `${preview.name} · ${(preview.size_bytes / 1024).toFixed(0)}KB` : ""}
        downloadUrl={preview ? `${fullUrl(preview.id)}?download=1` : ""}
      />
      {/* v0.4.53：文档分页预览接入缩放组件（与任务总览一致），翻页自动重置缩放。 */}
      <ZoomableImageDialog
        open={!!docPreview}
        onClose={() => setDocPreview(null)}
        src={docPreview ? previewUrl(docPreview.artifact.id, docPreview.page) : ""}
        title={docPreview?.artifact.note || docPreview?.artifact.name || ""}
        description={
          docPreview
            ? `${docPreview.artifact.name} · 第 ${docPreview.page} / ${docPreview.artifact.preview_pages ?? 0} 页`
            : ""
        }
        downloadUrl={docPreview ? downloadUrl(docPreview.artifact.id) : ""}
        footer={
          docPreview ? (
            <div className="flex items-center justify-center gap-2">
              <Button
                size="sm"
                variant="outline"
                disabled={docPreview.page <= 1}
                onClick={() => setDocPreview((cur) => (cur ? { ...cur, page: cur.page - 1 } : cur))}
              >
                <ChevronLeftIcon className="size-3.5" /> 上一页
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={docPreview.page >= (docPreview.artifact.preview_pages ?? 1)}
                onClick={() => setDocPreview((cur) => (cur ? { ...cur, page: cur.page + 1 } : cur))}
              >
                下一页 <ChevronRightIcon className="size-3.5" />
              </Button>
            </div>
          ) : null
        }
      />
      {pickerDialog}
      <ArtifactDataViewerDialog
        taskId={taskId!}
        artifact={dataPreview}
        open={!!dataPreview}
        onClose={() => setDataPreview(null)}
      />
    </>
  );
}
