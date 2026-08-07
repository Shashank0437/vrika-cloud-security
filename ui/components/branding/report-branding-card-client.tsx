"use client";

import { ImageIcon, Trash2Icon, UploadIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useRef, useState } from "react";

import { deleteTenantLogo, uploadTenantLogo } from "@/actions/branding/branding";
import {
  Button,
  Card,
  CardContent,
  CardHeader,
  useToast,
} from "@/components/shadcn";
import { cn } from "@/lib/utils";
import { TenantBrandingAttributes } from "@/types/branding";

const ALLOWED_TYPES = ["image/png", "image/jpeg"] as const;
const MAX_LOGO_BYTES = 2 * 1024 * 1024;

const readFileAsDataUrl = (file: File): Promise<string> =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });

interface ReportBrandingCardClientProps {
  branding: TenantBrandingAttributes | null;
}

export const ReportBrandingCardClient = ({
  branding,
}: ReportBrandingCardClientProps) => {
  const router = useRouter();
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [previewUrl, setPreviewUrl] = useState<string | null>(
    branding?.logo ?? null,
  );
  const [hasCustomLogo, setHasCustomLogo] = useState<boolean>(
    branding?.has_custom_logo ?? false,
  );
  const [currentFilename, setCurrentFilename] = useState<string>(
    branding?.logo_filename ?? "",
  );
  const [isUploading, setIsUploading] = useState(false);
  const [isRemoving, setIsRemoving] = useState(false);

  const handleSelectClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = async (
    event: React.ChangeEvent<HTMLInputElement>,
  ) => {
    const file = event.target.files?.[0];
    // Reset so selecting the same file again re-triggers change.
    event.target.value = "";
    if (!file) return;

    if (!ALLOWED_TYPES.includes(file.type as (typeof ALLOWED_TYPES)[number])) {
      toast({
        variant: "destructive",
        title: "Unsupported file",
        description: "Please upload a PNG or JPEG image.",
      });
      return;
    }

    if (file.size > MAX_LOGO_BYTES) {
      toast({
        variant: "destructive",
        title: "File too large",
        description: "The logo must be 2 MB or smaller.",
      });
      return;
    }

    setIsUploading(true);
    try {
      const dataUrl = await readFileAsDataUrl(file);
      const result = await uploadTenantLogo({
        logo_base64: dataUrl,
        logo_content_type: file.type,
        logo_filename: file.name,
      });

      if (result?.error || result?.errors) {
        const description =
          result?.error ||
          result?.errors?.[0]?.detail ||
          "Failed to upload logo. Please try again.";
        toast({
          variant: "destructive",
          title: "Upload failed",
          description,
        });
        return;
      }

      const nextLogo: string | undefined = result?.data?.attributes?.logo;
      setPreviewUrl(nextLogo ?? dataUrl);
      setHasCustomLogo(true);
      setCurrentFilename(file.name);
      toast({
        title: "Logo updated",
        description: "Your logo will be used on generated reports.",
      });
      router.refresh();
    } catch {
      toast({
        variant: "destructive",
        title: "Upload failed",
        description: "Could not read the selected file. Please try again.",
      });
    } finally {
      setIsUploading(false);
    }
  };

  const handleRemove = async () => {
    setIsRemoving(true);
    try {
      const result = await deleteTenantLogo();
      if (result?.error) {
        toast({
          variant: "destructive",
          title: "Remove failed",
          description: result.error,
        });
        return;
      }
      setPreviewUrl(null);
      setHasCustomLogo(false);
      setCurrentFilename("");
      toast({
        title: "Logo removed",
        description: "Reports will use the default logo.",
      });
      router.refresh();
    } finally {
      setIsRemoving(false);
    }
  };

  const isBusy = isUploading || isRemoving;

  return (
    <Card variant="inner" padding="none" className="gap-4 p-4 md:p-5">
      <CardHeader>
        <div className="flex flex-col gap-1">
          <h4 className="text-lg font-bold">Report Branding</h4>
          <p className="text-xs text-gray-500">
            Upload your organization&apos;s logo to appear on generated PDF
            reports. If no logo is set, the default logo is used. PNG or JPEG,
            up to 2 MB.
          </p>
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
          <div
            className={cn(
              "flex h-24 w-48 shrink-0 items-center justify-center overflow-hidden rounded-md border border-dashed",
              "border-gray-300 bg-gray-50 dark:border-gray-700 dark:bg-gray-900",
            )}
          >
            {previewUrl ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                src={previewUrl}
                alt="Report logo preview"
                className="max-h-full max-w-full object-contain"
              />
            ) : (
              <div className="flex flex-col items-center gap-1 text-gray-400">
                <ImageIcon className="size-6" />
                <span className="text-xs">Default logo</span>
              </div>
            )}
          </div>

          <div className="flex flex-1 flex-col gap-2">
            <div className="flex flex-wrap gap-2">
              <Button size="sm" onClick={handleSelectClick} disabled={isBusy}>
                <UploadIcon className="size-4" />
                {isUploading
                  ? "Uploading..."
                  : hasCustomLogo
                    ? "Replace logo"
                    : "Upload logo"}
              </Button>
              {hasCustomLogo && (
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={handleRemove}
                  disabled={isBusy}
                >
                  <Trash2Icon className="size-4" />
                  {isRemoving ? "Removing..." : "Remove"}
                </Button>
              )}
            </div>
            {hasCustomLogo && currentFilename && (
              <p className="text-xs text-gray-500">
                Current file: {currentFilename}
              </p>
            )}
          </div>
        </div>

        <input
          ref={fileInputRef}
          type="file"
          accept="image/png,image/jpeg"
          className="hidden"
          onChange={handleFileChange}
        />
      </CardContent>
    </Card>
  );
};
