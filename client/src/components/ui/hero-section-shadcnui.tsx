import { Button } from "@/components/ui/button";
import { motion, type Variants } from "framer-motion";
import { ArrowRight, Sparkles } from "lucide-react";

interface HeroSectionProps {
  onLaunch: () => void;
  status?: string;
}

export function HeroSection({ onLaunch, status }: HeroSectionProps) {
  const containerVariants: Variants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.15,
        delayChildren: 0.1,
      },
    },
  };

  const itemVariants: Variants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.5, ease: "easeOut" },
    },
  };

  const isConnecting = !status || status === "connecting";

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="flex min-h-[500px] flex-col items-center justify-center px-4 py-16 text-center"
    >
      <motion.div variants={itemVariants} className="mb-4">
        <span className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/10 px-4 py-1.5 text-sm font-medium text-[var(--muted-foreground)]">
          <Sparkles className="h-4 w-4" />
          Real-time Network Visualization
        </span>
      </motion.div>

      <motion.h1
        variants={itemVariants}
        className="mb-6 text-5xl font-bold tracking-tight md:text-7xl"
      >
        Map Your Network
        <br />
        <span className="bg-gradient-to-r from-white to-white/60 bg-clip-text text-transparent">
          In Real Time
        </span>
      </motion.h1>

      <motion.p
        variants={itemVariants}
        className="mb-8 max-w-2xl text-lg text-[var(--foreground)]/70"
      >
        Visualize live packet flows across your network as an interactive 3D
        graph. Capture, filter, and analyze TCP, UDP, DNS, ARP and more —
        right from your browser.
      </motion.p>

      <motion.div variants={itemVariants} className="flex flex-col items-center gap-3">
        <Button size="lg" className="gap-2" onClick={onLaunch}>
          Launch pacmap
          <ArrowRight className="h-4 w-4" />
        </Button>
        {isConnecting && (
          <p className="text-xs text-[var(--foreground)]/40">
            <span className="mr-1.5 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-current align-middle" />
            connecting to capture daemon…
          </p>
        )}
      </motion.div>

      <motion.div
        variants={itemVariants}
        className="mt-12 flex items-center gap-8 text-sm text-[var(--foreground)]/60"
      >
        <div>
          <div className="text-2xl font-bold text-[var(--foreground)]">
            10k+
          </div>
          <div>Packets / day</div>
        </div>
        <div className="h-8 w-px bg-[var(--border)]" />
        <div>
          <div className="text-2xl font-bold text-[var(--foreground)]">5+</div>
          <div>Protocols</div>
        </div>
        <div className="h-8 w-px bg-[var(--border)]" />
        <div>
          <div className="text-2xl font-bold text-[var(--foreground)]">
            100%
          </div>
          <div>Open Source</div>
        </div>
      </motion.div>
    </motion.div>
  );
}
