import { useEffect, useState } from "react";
import { ApiError, send } from "../api";

// F-004 T-12 (AC-11, AC-12): the estimating aids, wherever an estimate is
// entered: the warnings (advice, never a refusal), the equivalent-bet
// prompt, and an illustrative curve of what the range implies.

interface Warning {
  code: string;
  pointer?: string;
  message: string;
}
interface Aid {
  warnings: Warning[];
  bet: string;
  preview: { shape: "beta_pert" | "point"; points: [number, number][] };
}

export function EstimateAids({
  unit,
  min,
  ml,
  max,
  confidence,
  requested,
}: {
  unit: string;
  min: string;
  ml: string;
  max: string;
  confidence: string;
  requested?: string;
}) {
  const [aid, setAid] = useState<Aid | null>(null);
  const [problem, setProblem] = useState("");
  useEffect(() => {
    if (!min || !ml || !max || !confidence) {
      setAid(null);
      setProblem("");
      return;
    }
    let live = true;
    const t = window.setTimeout(() => {
      send<Aid>("POST", "/api/v1/estimates/warnings", {
        unit,
        estimate: { min, ml, max, confidence },
        requested_confidence: requested,
      })
        .then((a) => {
          if (live) {
            setAid(a);
            setProblem("");
          }
        })
        .catch((err: unknown) => {
          if (!live) return;
          setAid(null);
          // Without a permission that enters estimates the aids do not
          // exist (404): show nothing. A range out of order is said once.
          setProblem(
            err instanceof ApiError && err.status === 422
              ? err.detail.replace(/^: /, "The range ")
              : "",
          );
        });
    }, 400);
    return () => {
      live = false;
      window.clearTimeout(t);
    };
  }, [unit, min, ml, max, confidence, requested]);

  if (!aid && !problem) return null;
  return (
    <div className="aids" aria-live="polite">
      {problem ? <p className="error-text">{problem}</p> : null}
      {aid && aid.warnings.length > 0 ? (
        <ul className="warnings" aria-label="Advice on this estimate">
          {aid.warnings.map((w) => (
            <li key={w.code}>{w.message}</li>
          ))}
        </ul>
      ) : null}
      {aid ? (
        <>
          <Curve preview={aid.preview} ml={ml} />
          <p className="bet">{aid.bet}</p>
        </>
      ) : null}
    </div>
  );
}

function Curve({ preview, ml }: { preview: Aid["preview"]; ml: string }) {
  const pts = preview.points;
  if (preview.shape !== "beta_pert" || pts.length < 2) {
    return <p className="muted">The range is a single value.</p>;
  }
  const [x0, x1] = [pts[0]![0], pts[pts.length - 1]![0]];
  const ymax = Math.max(...pts.map((p) => p[1])) || 1;
  const W = 240;
  const H = 60;
  const d = pts
    .map(
      (p, i) =>
        `${i ? "L" : "M"}${(((p[0] - x0) / (x1 - x0)) * W).toFixed(1)},${(H - (p[1] / ymax) * (H - 4)).toFixed(1)}`,
    )
    .join(" ");
  return (
    <figure className="curve">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        width={W}
        height={H}
        role="img"
        aria-label={`Illustrative curve of the range, peaking at the most likely value, ${ml}`}
      >
        <path d={d} fill="none" stroke="currentColor" strokeWidth="2" />
      </svg>
      <figcaption className="muted">
        Illustrative shape only: the simulation chooses its own distributions.
      </figcaption>
    </figure>
  );
}
