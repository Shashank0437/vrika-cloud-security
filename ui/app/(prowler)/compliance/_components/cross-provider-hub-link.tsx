import { SquareArrowOutUpRight } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/shadcn/button/button";

interface CrossProviderHubLinkProps {
  complianceId: string;
}

export const CrossProviderHubLink = ({
  complianceId,
}: CrossProviderHubLinkProps) => (
  <Button variant="link" size="link-xs" asChild>
    <Link
      href={`https://hub.prowler.com/compliance/${encodeURIComponent(complianceId)}`}
      target="_blank"
      rel="noopener noreferrer"
      prefetch={false}
    >
      View on Vrika Hub
      <SquareArrowOutUpRight />
    </Link>
  </Button>
);
