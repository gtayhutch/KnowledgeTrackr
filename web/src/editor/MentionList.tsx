import { forwardRef, useEffect, useImperativeHandle, useState } from "react";

export type MentionItem = {
  id: string;
  label: string;
  kind: "person" | "page";
  href?: string;
};

export type MentionListRef = {
  onKeyDown: (props: { event: KeyboardEvent }) => boolean;
};

type Props = {
  items: MentionItem[];
  command: (item: { id: string; label: string }) => void;
};

/** Dropdown for @-mentions of people and pages. */
export const MentionList = forwardRef<MentionListRef, Props>(
  function MentionList({ items, command }, ref) {
    const [index, setIndex] = useState(0);

    useEffect(() => setIndex(0), [items]);

    useImperativeHandle(ref, () => ({
      onKeyDown: ({ event }) => {
        if (event.key === "ArrowUp") {
          setIndex(
            (value) => (value + items.length - 1) % Math.max(items.length, 1),
          );
          return true;
        }
        if (event.key === "ArrowDown") {
          setIndex((value) => (value + 1) % Math.max(items.length, 1));
          return true;
        }
        if (event.key === "Enter") {
          const item = items[index];
          if (item) command({ id: item.id, label: item.label });
          return true;
        }
        return false;
      },
    }));

    if (items.length === 0) {
      return <div className="kt-mention-list">No matches</div>;
    }

    return (
      <div className="kt-mention-list">
        {items.map((item, itemIndex) => (
          <button
            key={`${item.kind}-${item.id}`}
            type="button"
            className={itemIndex === index ? "is-active" : undefined}
            onClick={() => command({ id: item.id, label: item.label })}
          >
            <span>{item.label}</span>
            <span className="kt-mention-kind">{item.kind}</span>
          </button>
        ))}
      </div>
    );
  },
);
