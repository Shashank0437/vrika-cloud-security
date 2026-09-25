import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { TrackedFinding } from "@/types/findings-triage";

const { refresh, push, loadNote, loadHistory, update, confirmRemoval } =
  vi.hoisted(() => ({
    refresh: vi.fn(),
    push: vi.fn(),
    loadNote: vi.fn(),
    loadHistory: vi.fn(),
    update: vi.fn(),
    confirmRemoval: vi.fn(),
  }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh, push }) }));
vi.mock("@/actions/findings/findings-triage", () => ({
  loadLatestFindingTriageNote: loadNote,
  loadFindingTriageHistory: loadHistory,
  updateFindingTriage: update,
  confirmFindingRemoval: confirmRemoval,
}));
vi.mock("@/components/shadcn/custom/custom-link", () => ({
  CustomLink: ({ href, children }: { href: string; children: ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));
vi.mock("@/components/shadcn/modal", () => ({
  Modal: ({
    open,
    title,
    children,
  }: {
    open: boolean;
    title: string;
    children: ReactNode;
  }) =>
    open ? (
      <div role="dialog" aria-label={title}>
        {children}
      </div>
    ) : null,
}));

import { TrackedFindings } from "./tracked-findings";

function finding(): TrackedFinding {
  return {
    id: "triage-id",
    attributes: {
      finding_uid: "stable-firewall-finding",
      provider_id: "provider-id",
      provider_alias: "My project",
      provider_type: "gcp",
      status: "resolved",
      resolution_reason: "resource_removed",
      observation: "resource_removed",
      observation_detail:
        "Confirmed by a complete GCP firewall inventory read.",
      snapshot: {
        finding_id: "expired-snapshot",
        result: "FAIL",
        title: "Restrict public RDP",
        observed_at: "2026-09-24T18:00:00Z",
        resources: [
          {
            name: "default-allow-rdp",
            uid: "123",
            service: "compute",
            type: "Firewall",
            region: "global",
          },
        ],
      },
      notes_count: 1,
      can_edit: false,
      can_manage_exceptions: false,
      updated_at: "2026-09-24T18:20:00Z",
      verification_checked_at: "2026-09-24T18:20:00Z",
      observation_scan_id: "last-scan",
    },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  loadNote.mockResolvedValue({
    noteId: "note-id",
    noteBody: "Deleting the public rule",
  });
  loadHistory.mockResolvedValue({
    events: [
      {
        id: "manual-event",
        attributes: {
          kind: "status",
          actor_name: "Team member",
          inserted_at: "2026-09-24T18:00:00Z",
          changes: { status: { from: "open", to: "remediating" } },
        },
      },
      {
        id: "verification-event",
        attributes: {
          kind: "verification",
          actor_name: "Resource verification",
          inserted_at: "2026-09-24T18:20:00Z",
          changes: {
            status: { from: "remediating", to: "resolved" },
            reason: "Resource removed",
          },
        },
      },
    ],
    hasNext: false,
  });
});

describe("tracked findings", () => {
  it("requires explicit consent and evidence for provider-independent removal confirmation", async () => {
    const user = userEvent.setup();
    const row = finding();
    Object.assign(row.attributes, {
      provider_type: "azure",
      status: "remediating",
      resolution_reason: "",
      observation: "not_seen",
      can_edit: true,
      can_manage_exceptions: true,
    });
    confirmRemoval.mockResolvedValue(undefined);
    render(
      <TrackedFindings
        result={{ ok: true, value: { findings: [row], hasNext: false } }}
        page={1}
        status=""
        search=""
        providerId=""
      />,
    );
    await user.click(
      screen.getByRole("button", { name: "Confirm resource removal" }),
    );
    const dialog = screen.getByRole("dialog", {
      name: "Confirm resource removal",
    });
    const submit = within(dialog).getByRole("button", {
      name: "Confirm and resolve",
    });
    expect(submit).toBeDisabled();
    await user.type(
      within(dialog).getByLabelText("Removal evidence"),
      "Deletion confirmed in change CHG-123",
    );
    expect(submit).toBeDisabled();
    await user.click(within(dialog).getByRole("checkbox"));
    await user.click(submit);
    await waitFor(() =>
      expect(confirmRemoval).toHaveBeenCalledWith({
        triageId: row.id,
        findingId: "expired-snapshot",
        observationScanId: "last-scan",
        previousStatus: "remediating",
        evidence: "Deletion confirmed in change CHG-123",
        confirmRemoved: true,
      }),
    );
    expect(refresh).toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("does not offer confirmation to members or for observed findings", () => {
    const row = finding();
    Object.assign(row.attributes, {
      status: "remediating",
      observation: "not_seen",
      can_edit: true,
      can_manage_exceptions: false,
    });
    const { rerender } = render(
      <TrackedFindings
        result={{ ok: true, value: { findings: [row], hasNext: false } }}
        page={1}
        status=""
        search=""
        providerId=""
      />,
    );
    expect(
      screen.queryByRole("button", { name: "Confirm resource removal" }),
    ).not.toBeInTheDocument();
    Object.assign(row.attributes, {
      observation: "observed",
      can_manage_exceptions: true,
    });
    rerender(
      <TrackedFindings
        result={{ ok: true, value: { findings: [row], hasNext: false } }}
        page={1}
        status=""
        search=""
        providerId=""
      />,
    );
    expect(
      screen.queryByRole("button", { name: "Confirm resource removal" }),
    ).not.toBeInTheDocument();
  });

  it("retains evidence and shows the server conflict when confirmation is stale", async () => {
    const user = userEvent.setup();
    const row = finding();
    Object.assign(row.attributes, {
      status: "remediating",
      observation: "not_seen",
      can_edit: true,
      can_manage_exceptions: true,
    });
    confirmRemoval.mockRejectedValueOnce(
      new Error("Scan changed; refresh before confirming."),
    );
    render(
      <TrackedFindings
        result={{ ok: true, value: { findings: [row], hasNext: false } }}
        page={1}
        status=""
        search=""
        providerId=""
      />,
    );
    await user.click(
      screen.getByRole("button", { name: "Confirm resource removal" }),
    );
    const dialog = screen.getByRole("dialog", {
      name: "Confirm resource removal",
    });
    await user.type(
      within(dialog).getByLabelText("Removal evidence"),
      "Evidence retained",
    );
    await user.click(within(dialog).getByRole("checkbox"));
    await user.click(
      within(dialog).getByRole("button", { name: "Confirm and resolve" }),
    );
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Scan changed; refresh before confirming.",
    );
    expect(within(dialog).getByLabelText("Removal evidence")).toHaveValue(
      "Evidence retained",
    );
    expect(refresh).not.toHaveBeenCalled();
  });

  it("distinguishes reviewer confirmation from cloud verification and displays evidence in history", async () => {
    const row = finding();
    row.attributes.observation = "removal_confirmed";
    loadHistory.mockResolvedValueOnce({
      events: [
        {
          id: "confirmation",
          attributes: {
            kind: "verification",
            actor_name: "Reviewer",
            inserted_at: "2026-09-24T18:20:00Z",
            changes: {
              reason: "Reviewer confirmed removal.",
              verification: {
                method: "reviewer_confirmation",
                evidence: "Change CHG-123 confirms deletion",
              },
            },
          },
        },
      ],
      hasNext: false,
    });
    render(
      <TrackedFindings
        result={{ ok: true, value: { findings: [row], hasNext: false } }}
        page={1}
        status=""
        search=""
        providerId=""
      />,
    );
    expect(screen.getByText("Removal confirmed by reviewer")).toBeVisible();
    expect(screen.queryByText("Deletion verified")).not.toBeInTheDocument();
    await userEvent.click(
      screen.getByRole("button", { name: "Notes & history" }),
    );
    expect(
      await screen.findByText("Evidence: Change CHG-123 confirms deletion"),
    ).toBeVisible();
  });

  it("keeps removed resources visible without converting their historical FAIL to PASS", () => {
    render(
      <TrackedFindings
        result={{ ok: true, value: { findings: [finding()], hasNext: false } }}
        page={1}
        status=""
        search=""
        providerId=""
      />,
    );
    expect(screen.getByText("default-allow-rdp")).toBeVisible();
    expect(screen.getByText("FAIL")).toBeVisible();
    expect(screen.queryByText("PASS")).not.toBeInTheDocument();
    expect(screen.getByText("Resource removed")).toBeVisible();
    expect(screen.getByText("Deletion verified")).toBeVisible();
  });

  it("allows read-only users to see notes and both manual and automatic history after snapshot retention", async () => {
    render(
      <TrackedFindings
        result={{ ok: true, value: { findings: [finding()], hasNext: false } }}
        page={1}
        status=""
        search=""
        providerId=""
      />,
    );
    await userEvent.click(
      screen.getByRole("button", { name: "Notes & history" }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByDisplayValue("Deleting the public rule"),
    ).toBeDisabled();
    await waitFor(() =>
      expect(within(dialog).getByText(/Team member/)).toBeVisible(),
    );
    expect(within(dialog).getByText(/Resource verification/)).toBeVisible();
    expect(
      within(dialog).getByText("Resolution reason: Resource removed"),
    ).toBeVisible();
    expect(update).not.toHaveBeenCalled();
  });

  it("shows uncertainty rather than resolution when a resource is only missing", () => {
    const row = finding();
    row.attributes.status = "remediating";
    row.attributes.resolution_reason = "";
    row.attributes.observation = "not_seen";
    row.attributes.observation_detail = "Deletion has not been verified.";
    row.attributes.verification_checked_at = null;
    render(
      <TrackedFindings
        result={{ ok: true, value: { findings: [row], hasNext: false } }}
        page={1}
        status=""
        search=""
        providerId=""
      />,
    );
    expect(screen.getByText("Not seen in latest scan")).toBeVisible();
    expect(
      within(screen.getByRole("table")).getByText("Remediating"),
    ).toBeVisible();
    expect(screen.queryByText("Deletion verified")).not.toBeInTheDocument();
  });

  it("surfaces API and note errors instead of a success-shaped empty view", async () => {
    const { rerender } = render(
      <TrackedFindings
        result={{ ok: false, message: "Could not load tracked findings." }}
        page={1}
        status=""
        search=""
        providerId=""
      />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Could not load tracked findings.",
    );
    expect(screen.queryByText(/No tracked findings/)).not.toBeInTheDocument();
    loadNote.mockRejectedValueOnce(new Error("Note could not be loaded."));
    rerender(
      <TrackedFindings
        result={{ ok: true, value: { findings: [finding()], hasNext: false } }}
        page={1}
        status=""
        search=""
        providerId=""
      />,
    );
    await userEvent.click(
      screen.getByRole("button", { name: "Notes & history" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Note could not be loaded.",
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("preserves filters during pagination and resets pagination when filters change", async () => {
    const user = userEvent.setup();
    render(
      <TrackedFindings
        result={{ ok: true, value: { findings: [], hasNext: true } }}
        page={2}
        status="resolved"
        search="rdp"
        providerId="provider-id"
      />,
    );
    expect(screen.getByRole("link", { name: "Next" })).toHaveAttribute(
      "href",
      "/findings/triage?page=3&status=resolved&search=rdp&providerId=provider-id",
    );
    await user.selectOptions(
      screen.getByLabelText("Triage status"),
      "remediating",
    );
    await user.click(screen.getByRole("button", { name: "Apply filters" }));
    expect(push).toHaveBeenCalledWith(
      "/findings/triage?search=rdp&status=remediating&providerId=provider-id",
    );
  });
});
