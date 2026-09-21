import { useMemo } from 'react';
import { detectThreats } from './core/threat-engine/detectThreats';
import { buildThreatViews } from './core/threat-engine/buildThreatViews';
import { getThreatLibrary } from './threat-library/loader/bundledLibrary';
import {
  selectActiveBoundaries,
  selectActiveEdges,
  selectActiveManualThreats,
  selectActiveNodes,
  useDiagramStore,
} from './core/state/diagramStore';
import { useDragInteractions } from './core/state/useDragInteractions';
import { useUndoRedo } from './core/state/useUndoRedo';
import { usePersistence } from './features/persistence/usePersistence';
import { useLocalePersistence } from './features/persistence/useLocalePersistence';
import { useCustomRules } from './features/custom-rules/useCustomRules';
import { selectCustomLibraries, useCustomRulesStore } from './features/custom-rules/store';
import { mergeThreatRules } from './features/custom-rules/mergeRules';
import { useLocale, useT } from './i18n';
import { Canvas } from './core/canvas/Canvas';
import { Legend } from './core/canvas/Legend';
import { LeftSidebar } from './ui/LeftSidebar';
import { RightSidebar } from './ui/RightSidebar';
import { TopControls } from './ui/TopControls';
import { LinkingIndicator } from './ui/LinkingIndicator';
import { ProjectEditModal } from './ui/panels/ProjectEditModal';
import { ComplianceMapModal } from './ui/panels/ComplianceMapModal';
import { AnalyticsModal } from './ui/panels/AnalyticsModal';
import { ManualThreatModal } from './ui/panels/ManualThreatModal';
import { CustomRulesManagerModal } from './ui/panels/CustomRulesManagerModal';
import { TemplateModal } from './ui/panels/TemplateModal';
import { ProjectFileModal } from './ui/panels/ProjectFileModal';
import { NewProjectModal } from './ui/panels/NewProjectModal';
import { LibraryInspectorModal } from './ui/panels/library-inspector/LibraryInspectorModal';

export default function App() {
  const t = useT();
  const [locale] = useLocale();
  useDragInteractions();
  useUndoRedo();
  usePersistence();
  useLocalePersistence();
  useCustomRules();

  const isHydrated = useDiagramStore((s) => s.isHydrated);
  const customLibraries = useCustomRulesStore(selectCustomLibraries);
  const nodes = useDiagramStore(selectActiveNodes);
  const edges = useDiagramStore(selectActiveEdges);
  const boundaries = useDiagramStore(selectActiveBoundaries);
  const activeFramework = useDiagramStore((s) => s.activeFramework);
  const isFocusMode = useDiagramStore((s) => s.isFocusMode);
  const linkingFromId = useDiagramStore((s) => s.linkingFromId);
  const manualThreats = useDiagramStore(selectActiveManualThreats);
  const suppressions = useDiagramStore((s) => s.suppressions);
  const riskScores = useDiagramStore((s) => s.riskScores);
  const controlStatuses = useDiagramStore((s) => s.controlStatuses);
  const isLibraryInspectorOpen = useDiagramStore((s) => s.isLibraryInspectorOpen);
  const closeLibraryInspector = useDiagramStore((s) => s.closeLibraryInspector);

  // 出荷ルール + 有効なカスタムルールライブラリを合流（id 衝突は bundled 優先で除外）。
  const merged = useMemo(
    () => mergeThreatRules(getThreatLibrary(locale).rules, customLibraries),
    [customLibraries, locale],
  );

  const threats = useMemo(
    () =>
      buildThreatViews({
        detected: detectThreats({
          nodes,
          edges,
          framework: activeFramework,
          rules: merged.rules,
          boundaries,
        }),
        manualThreats,
        nodes,
        framework: activeFramework,
        suppressions,
        riskScores,
        controlStatuses,
        customRuleIds: merged.customRuleIds,
      }),
    [
      nodes,
      edges,
      boundaries,
      activeFramework,
      manualThreats,
      suppressions,
      riskScores,
      controlStatuses,
      merged,
    ],
  );

  if (!isHydrated) {
    return (
      <div className="flex h-screen items-center justify-center bg-slate-950 text-slate-400 text-sm">
        {t('app.loading')}
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans select-none">
      {!isFocusMode && <LeftSidebar threats={threats} />}

      <Canvas threats={threats}>
        <TopControls />
        <Legend />
        {linkingFromId && <LinkingIndicator />}
      </Canvas>

      {!isFocusMode && <RightSidebar threats={threats} />}

      <ProjectEditModal />
      <ComplianceMapModal />
      <AnalyticsModal threats={threats} />
      <ManualThreatModal />
      <CustomRulesManagerModal />
      <TemplateModal />
      <ProjectFileModal />
      <NewProjectModal />
      {isLibraryInspectorOpen && <LibraryInspectorModal onClose={closeLibraryInspector} />}
    </div>
  );
}
