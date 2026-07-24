"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { CloudCog, Loader2, Rocket } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { Controller, useForm, useWatch } from "react-hook-form";
import { z } from "zod";

import { getComplianceFrameworks } from "@/actions/compliances";
import { scanOnDemand } from "@/actions/scans";
import { getSchedule } from "@/actions/schedules";
import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import { Field, FieldError, FieldLabel, Input } from "@/components/shadcn";
import { FormButtons } from "@/components/shadcn/form";
import { Modal } from "@/components/shadcn/modal";
import {
  RadioGroup,
  RadioGroupItem,
} from "@/components/shadcn/radio-group/radio-group";
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectSelectAll,
  MultiSelectSeparator,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import { toast, ToastAction } from "@/components/shadcn/toast";
import { CloudFeatureBadgeLink } from "@/components/shared/cloud-feature-badge";
import { UsageLimitMessage } from "@/components/shared/usage-limit-message";
import { getActionErrorMessage, hasActionError } from "@/lib/action-errors";
import {
  buildScheduleAttributesFromProvider,
  getScanScheduleCapability,
  getScheduleFormDefaults,
  getScheduleFormValues,
  scheduleFormSchema,
} from "@/lib/schedules";
import { isCloud } from "@/lib/shared/env";
import { isVrikaEmbedMode } from "@/lib/vrika-embed";
import { SCAN_JOBS_TAB } from "@/types";
import type {
  ComplianceFrameworkCatalogItem,
  ComplianceFrameworksResponse,
} from "@/types/compliance";
import type { ProviderProps } from "@/types/providers";
import {
  SCAN_SCHEDULE_CAPABILITY,
  type ScanScheduleCapability,
  type ScheduleApiResponse,
  type ScheduleFormValues,
} from "@/types/schedules";

import { scanAliasSchema } from "./scan-alias-validation";
import { getScanJobsTab } from "./scans.utils";
import {
  SAVE_SCHEDULE_STATUS,
  saveScheduleWithInitialScan,
} from "./schedule/save-schedule";
import { ScanScheduleFields } from "./schedule/scan-schedule-fields";

const COMPLIANCE_SCOPE = {
  ALL: "all",
  SPECIFIC: "specific",
} as const;

type ComplianceScope = (typeof COMPLIANCE_SCOPE)[keyof typeof COMPLIANCE_SCOPE];

const launchScanSchema = z
  .object({
    providerId: z.string().min(1, "Select a provider to launch a scan."),
    scanAlias: scanAliasSchema.optional(),
    complianceScope: z.enum([COMPLIANCE_SCOPE.ALL, COMPLIANCE_SCOPE.SPECIFIC]),
    complianceIds: z.array(z.string()),
  })
  .superRefine((values, ctx) => {
    if (
      values.complianceScope === COMPLIANCE_SCOPE.SPECIFIC &&
      values.complianceIds.length === 0
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Select at least one compliance framework.",
        path: ["complianceIds"],
      });
    }
  });

type LaunchScanFormValues = z.infer<typeof launchScanSchema>;

const LAUNCH_MODE = {
  NOW: "now",
  SCHEDULE: "schedule",
} as const;

type LaunchMode = (typeof LAUNCH_MODE)[keyof typeof LAUNCH_MODE];

const SCHEDULE_LOAD_STATE = {
  IDLE: "idle",
  LOADING: "loading",
  LOADED: "loaded",
  ERROR: "error",
} as const;

type ScheduleLoadState =
  (typeof SCHEDULE_LOAD_STATE)[keyof typeof SCHEDULE_LOAD_STATE];

const FRAMEWORK_LOAD_STATE = {
  IDLE: "idle",
  LOADING: "loading",
  LOADED: "loaded",
  ERROR: "error",
} as const;

type FrameworkLoadState =
  (typeof FRAMEWORK_LOAD_STATE)[keyof typeof FRAMEWORK_LOAD_STATE];

interface LaunchScanModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  providers: ProviderProps[];
  /** Cloud overlay seam; defaults to the environment-resolved capability. */
  capability?: ScanScheduleCapability;
  isScanLimitReached?: boolean;
}

interface LaunchScanFormProps {
  providers: ProviderProps[];
  onClose: () => void;
  capability: ScanScheduleCapability;
  isScanLimitReached: boolean;
}

function frameworkDisplayLabel(item: ComplianceFrameworkCatalogItem): string {
  const { name, framework, version } = item.attributes;
  const base = name || framework || item.id;
  return version ? `${base} (${version})` : base;
}

function LaunchScanForm({
  providers,
  onClose,
  capability,
  isScanLimitReached,
}: LaunchScanFormProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const form = useForm<LaunchScanFormValues>({
    resolver: zodResolver(launchScanSchema),
    defaultValues: {
      providerId: "",
      scanAlias: "",
      complianceScope: COMPLIANCE_SCOPE.ALL,
      complianceIds: [],
    },
  });
  const scheduleForm = useForm<ScheduleFormValues>({
    resolver: zodResolver(scheduleFormSchema),
    defaultValues: getScheduleFormDefaults(),
  });
  const [mode, setMode] = useState<LaunchMode>(LAUNCH_MODE.NOW);
  const [scheduleLoad, setScheduleLoad] = useState<ScheduleLoadState>(
    SCHEDULE_LOAD_STATE.IDLE,
  );
  const [frameworks, setFrameworks] = useState<
    ComplianceFrameworkCatalogItem[]
  >([]);
  const [frameworkLoad, setFrameworkLoad] = useState<FrameworkLoadState>(
    FRAMEWORK_LOAD_STATE.IDLE,
  );
  // Guards against out-of-order responses when switching providers quickly.
  const requestedProviderRef = useRef<string>("");
  const requestedFrameworkProviderTypeRef = useRef<string>("");

  const isAdvanced = capability === SCAN_SCHEDULE_CAPABILITY.ADVANCED;
  const isManualOnly = capability === SCAN_SCHEDULE_CAPABILITY.MANUAL_ONLY;
  const isBlocked =
    capability === SCAN_SCHEDULE_CAPABILITY.BLOCKED ||
    (isManualOnly && isScanLimitReached);
  const isScheduleMode = isAdvanced && mode === LAUNCH_MODE.SCHEDULE;

  // useWatch, not form.watch: form.watch re-renders are dropped by React Compiler memoization.
  const providerId = useWatch({ control: form.control, name: "providerId" });
  const complianceScope = useWatch({
    control: form.control,
    name: "complianceScope",
  });
  const complianceIds = useWatch({
    control: form.control,
    name: "complianceIds",
  });
  const activeTab = getScanJobsTab(searchParams.get("tab") ?? undefined);
  const shouldShowActiveTabAction = activeTab !== SCAN_JOBS_TAB.ACTIVE;
  const disconnectedProviderIds = providers
    .filter((provider) => provider.attributes.connection.connected !== true)
    .map((provider) => provider.id);

  const selectedProvider = providers.find(
    (provider) => provider.id === providerId,
  );
  const selectedProviderType = selectedProvider?.attributes.provider;

  const getProviderScheduleAttributes = (id: string) => {
    const provider = providers.find((item) => item.id === id);

    return provider
      ? buildScheduleAttributesFromProvider(provider.attributes)
      : undefined;
  };

  const loadFrameworks = async (providerType: string) => {
    requestedFrameworkProviderTypeRef.current = providerType;
    setFrameworkLoad(FRAMEWORK_LOAD_STATE.LOADING);
    const response = (await getComplianceFrameworks(providerType)) as
      | ComplianceFrameworksResponse
      | { error?: string }
      | undefined;

    if (requestedFrameworkProviderTypeRef.current !== providerType) return;

    if (
      !response ||
      ("error" in response && response.error) ||
      !("data" in response)
    ) {
      setFrameworks([]);
      setFrameworkLoad(FRAMEWORK_LOAD_STATE.ERROR);
      return;
    }

    setFrameworks(response.data ?? []);
    setFrameworkLoad(FRAMEWORK_LOAD_STATE.LOADED);
  };

  useEffect(() => {
    if (!selectedProviderType) {
      setFrameworks([]);
      setFrameworkLoad(FRAMEWORK_LOAD_STATE.IDLE);
      return;
    }
    void loadFrameworks(selectedProviderType);
  }, [selectedProviderType]);

  const loadSchedule = async (id: string) => {
    requestedProviderRef.current = id;
    if (!id) {
      setScheduleLoad(SCHEDULE_LOAD_STATE.IDLE);
      return;
    }

    const providerScheduleAttributes = getProviderScheduleAttributes(id);
    if (providerScheduleAttributes) {
      scheduleForm.reset(getScheduleFormValues(providerScheduleAttributes));
      setScheduleLoad(SCHEDULE_LOAD_STATE.LOADED);
      return;
    }

    setScheduleLoad(SCHEDULE_LOAD_STATE.LOADING);
    const response = (await getSchedule(id)) as
      | ScheduleApiResponse
      | { error?: string };

    if (requestedProviderRef.current !== id) return;

    // No advanced schedule API (OSS 405) or empty body → use form defaults.
    // Still an error for unexpected failures so the user knows saving may overwrite.
    if (!response || ("error" in response && response.error)) {
      if (isVrikaEmbedMode()) {
        scheduleForm.reset(getScheduleFormDefaults());
        setScheduleLoad(SCHEDULE_LOAD_STATE.LOADED);
        return;
      }
      setScheduleLoad(SCHEDULE_LOAD_STATE.ERROR);
      return;
    }

    scheduleForm.reset(
      getScheduleFormValues(
        "data" in response ? response.data?.attributes : null,
      ),
    );
    setScheduleLoad(SCHEDULE_LOAD_STATE.LOADED);
  };

  const handleProviderChange = (id: string) => {
    form.setValue("providerId", id, { shouldValidate: true });
    form.setValue("complianceIds", []);
    if (isScheduleMode) void loadSchedule(id);
  };

  const handleModeChange = (nextMode: string) => {
    if (nextMode === LAUNCH_MODE.SCHEDULE && !isAdvanced) return;
    setMode(nextMode as LaunchMode);
    if (nextMode === LAUNCH_MODE.SCHEDULE) void loadSchedule(providerId);
  };

  const handleComplianceScopeChange = (nextScope: string) => {
    form.setValue("complianceScope", nextScope as ComplianceScope, {
      shouldValidate: true,
    });
    if (nextScope === COMPLIANCE_SCOPE.ALL) {
      form.setValue("complianceIds", [], { shouldValidate: true });
    }
  };

  const selectedCompliances =
    complianceScope === COMPLIANCE_SCOPE.SPECIFIC ? complianceIds : [];

  const launchNow = form.handleSubmit(
    async ({
      providerId: id,
      scanAlias,
      complianceScope: scope,
      complianceIds: ids,
    }) => {
      if (isBlocked) return;

      const formData = new FormData();
      formData.set("providerId", id);
      const trimmedAlias = scanAlias?.trim();
      if (trimmedAlias) {
        formData.set("scanName", trimmedAlias);
      }
      if (scope === COMPLIANCE_SCOPE.SPECIFIC && ids.length > 0) {
        formData.set("compliances", JSON.stringify(ids));
      }

      const result = await scanOnDemand(formData);

      if (hasActionError(result)) {
        form.setError("root", { message: getActionErrorMessage(result) });
        return;
      }

      if (result?.errors && result.errors.length > 0) {
        form.setError("root", {
          message: String(result.errors[0]?.detail ?? "Failed to launch scan."),
        });
        return;
      }

      toast({
        title: "Scan launched",
        description: "The scan was launched successfully.",
        action: shouldShowActiveTabAction ? (
          <ToastAction altText="View scan in progress" asChild>
            <Link href="/scans?tab=active">View scan</Link>
          </ToastAction>
        ) : undefined,
      });
      onClose();
      router.refresh();
    },
  );

  const saveSchedule = async () => {
    if (isBlocked || !isAdvanced) return;

    const providerValid = await form.trigger([
      "providerId",
      "complianceScope",
      "complianceIds",
    ]);
    if (!providerValid) return;

    await scheduleForm.handleSubmit(async (values) => {
      const result = await saveScheduleWithInitialScan({
        providerId: form.getValues("providerId"),
        values,
        compliances: selectedCompliances,
      });

      if (result.status === SAVE_SCHEDULE_STATUS.ERROR) {
        form.setError("root", { message: result.message });
        return;
      }

      const launched =
        result.status === SAVE_SCHEDULE_STATUS.SAVED_AND_LAUNCHED;
      toast({
        title: launched
          ? "Scan schedule saved and initial scan launched"
          : "Scan schedule saved",
        description:
          result.status === SAVE_SCHEDULE_STATUS.SAVED_SCAN_FAILED
            ? `The schedule was saved, but the initial scan could not be launched: ${result.message}`
            : launched
              ? "The schedule was saved and the initial scan was launched."
              : "The scan schedule was saved successfully.",
        action: (
          <ToastAction altText="View scheduled scans" asChild>
            <Link href={`/scans?tab=${SCAN_JOBS_TAB.SCHEDULED}`}>
              View schedule
            </Link>
          </ToastAction>
        ),
      });
      onClose();
      router.refresh();
    })();
  };

  const onSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (isBlocked) return;

    if (isScheduleMode) {
      void saveSchedule();
      return;
    }
    void launchNow();
  };

  const providerError = form.formState.errors.providerId?.message;
  const aliasError = form.formState.errors.scanAlias?.message;
  const complianceError = form.formState.errors.complianceIds?.message;
  const rootError = form.formState.errors.root?.message;
  const isSubmitting =
    form.formState.isSubmitting || scheduleForm.formState.isSubmitting;
  const isScheduleLoading = scheduleLoad === SCHEDULE_LOAD_STATE.LOADING;
  const isFrameworkLoading = frameworkLoad === FRAMEWORK_LOAD_STATE.LOADING;
  const isSpecificCompliance = complianceScope === COMPLIANCE_SCOPE.SPECIFIC;

  return (
    // min-w-0: let this dialog grid item shrink so a long provider UID truncates instead of widening the modal
    <form onSubmit={onSubmit} className="flex min-w-0 flex-col gap-8">
      <div className="flex items-center gap-2">
        <CloudCog className="text-text-neutral-secondary size-4" />
        <span className="text-text-neutral-secondary text-sm">
          Select the provider you would like to scan
        </span>
      </div>

      <Field>
        <FieldLabel htmlFor="launch-scan-account">Providers</FieldLabel>
        <AccountsSelector
          id="launch-scan-account"
          providers={providers}
          disabledValues={disconnectedProviderIds}
          onBatchChange={(_, values) =>
            handleProviderChange(values.at(-1) ?? "")
          }
          selectedValues={providerId ? [providerId] : []}
          closeOnSelect
          placeholder="Select a Provider"
          emptySelectionLabel="No provider selected"
          clearSelectionLabel="Clear provider selection"
        />
        {providerError && <FieldError>{providerError}</FieldError>}
      </Field>

      {!isManualOnly && !isBlocked && (
        <Field>
          <FieldLabel>Mode</FieldLabel>
          <RadioGroup
            value={mode}
            onValueChange={handleModeChange}
            className="flex flex-row flex-wrap gap-6"
            aria-label="Scan mode"
          >
            <label className="flex items-center gap-2 text-sm">
              <RadioGroupItem value={LAUNCH_MODE.NOW} aria-label="Run now" />
              Run now
            </label>
            <label className="flex items-center gap-2 text-sm">
              <RadioGroupItem
                value={LAUNCH_MODE.SCHEDULE}
                aria-label="On a schedule"
                disabled={!isAdvanced}
              />
              On a schedule
              {!isAdvanced && <CloudFeatureBadgeLink size="sm" />}
            </label>
          </RadioGroup>
        </Field>
      )}

      <Field>
        <FieldLabel>Compliance</FieldLabel>
        <RadioGroup
          value={complianceScope}
          onValueChange={handleComplianceScopeChange}
          className="flex flex-row flex-wrap gap-6"
          aria-label="Compliance scope"
        >
          <label className="flex items-center gap-2 text-sm">
            <RadioGroupItem
              value={COMPLIANCE_SCOPE.ALL}
              aria-label="All compliance"
            />
            All compliance
          </label>
          <label className="flex items-center gap-2 text-sm">
            <RadioGroupItem
              value={COMPLIANCE_SCOPE.SPECIFIC}
              aria-label="Specific compliance"
              disabled={!providerId}
            />
            Specific compliance
          </label>
        </RadioGroup>
      </Field>

      {isSpecificCompliance && (
        <Field>
          <FieldLabel>Frameworks</FieldLabel>
          {isFrameworkLoading ? (
            <div className="flex items-center gap-3 py-2">
              <Loader2 className="size-5 animate-spin" />
              <span className="text-sm">Loading frameworks...</span>
            </div>
          ) : frameworkLoad === FRAMEWORK_LOAD_STATE.ERROR ? (
            <FieldError>
              Failed to load compliance frameworks for this provider.
            </FieldError>
          ) : (
            <Controller
              control={form.control}
              name="complianceIds"
              render={({ field }) => (
                <MultiSelect
                  values={field.value}
                  onValuesChange={(values) => {
                    field.onChange(values);
                    form.clearErrors("complianceIds");
                  }}
                >
                  <MultiSelectTrigger size="default" aria-label="Frameworks">
                    <MultiSelectValue placeholder="Select compliance frameworks" />
                  </MultiSelectTrigger>
                  <MultiSelectContent
                    search={{ placeholder: "Search frameworks..." }}
                  >
                    <MultiSelectSelectAll>Select All</MultiSelectSelectAll>
                    <MultiSelectSeparator />
                    {frameworks.map((item) => (
                      <MultiSelectItem key={item.id} value={item.id}>
                        {frameworkDisplayLabel(item)}
                      </MultiSelectItem>
                    ))}
                  </MultiSelectContent>
                </MultiSelect>
              )}
            />
          )}
          {complianceError && <FieldError>{complianceError}</FieldError>}
        </Field>
      )}

      {!isScheduleMode && (
        <Field>
          <FieldLabel htmlFor="launch-scan-alias">Alias (optional)</FieldLabel>
          <Input
            id="launch-scan-alias"
            aria-label="Alias"
            {...form.register("scanAlias")}
          />
          {aliasError && <FieldError>{aliasError}</FieldError>}
        </Field>
      )}

      {isBlocked && <UsageLimitMessage />}

      {isScheduleMode && isScheduleLoading && (
        <div className="flex items-center gap-3 py-2">
          <Loader2 className="size-5 animate-spin" />
          <span className="text-sm">Loading scan schedule...</span>
        </div>
      )}

      {isScheduleMode && scheduleLoad === SCHEDULE_LOAD_STATE.ERROR && (
        <FieldError>
          Failed to load the current scan schedule. Saving will overwrite it.
        </FieldError>
      )}

      {isScheduleMode && !isScheduleLoading && (
        <ScanScheduleFields
          form={scheduleForm}
          disabled={isSubmitting || !providerId}
          showLaunchInitialScan
          showNextScheduledCopy
        />
      )}

      {rootError && <FieldError>{rootError}</FieldError>}

      <FormButtons
        onCancel={onClose}
        submitText={
          isSubmitting
            ? isScheduleMode
              ? "Saving..."
              : "Launching..."
            : isScheduleMode
              ? "Save Schedule"
              : "Launch Scan"
        }
        loadingText={isScheduleMode ? "Saving..." : "Launching..."}
        isDisabled={
          isSubmitting ||
          !providers.length ||
          isScheduleLoading ||
          isBlocked ||
          (isScheduleMode && !providerId) ||
          (isSpecificCompliance && isFrameworkLoading)
        }
        rightIcon={<Rocket className="size-4" />}
      />
    </form>
  );
}

export function LaunchScanModal({
  open,
  onOpenChange,
  providers,
  capability,
  isScanLimitReached = false,
}: LaunchScanModalProps) {
  const resolvedCapability = capability ?? getScanScheduleCapability(isCloud());

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Launch A Scan"
      size="xl"
      className="gap-8"
    >
      <LaunchScanForm
        providers={providers}
        onClose={() => onOpenChange(false)}
        capability={resolvedCapability}
        isScanLimitReached={isScanLimitReached}
      />
    </Modal>
  );
}
