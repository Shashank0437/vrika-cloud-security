import ReactMarkdown from "react-markdown";

import { remarkVrikaBranding } from "@/lib/branding";

interface MarkdownContainerProps {
  children: string;
}

export const MarkdownContainer = ({ children }: MarkdownContainerProps) => (
  <div className="prose prose-sm dark:prose-invert prose-code:before:content-none prose-code:after:content-none max-w-none break-words whitespace-normal">
    <ReactMarkdown remarkPlugins={[remarkVrikaBranding]}>
      {children}
    </ReactMarkdown>
  </div>
);
