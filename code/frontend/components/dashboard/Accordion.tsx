"use client";

import type { ReactNode } from "react";
import styles from "./Accordion.module.css";

export interface AccordionItem {
  id: string;
  header: ReactNode;
  content: ReactNode;
}

interface AccordionProps {
  items: AccordionItem[];
  emptyMessage: string;
}

export const Accordion = ({ items, emptyMessage }: AccordionProps) => {
  if (items.length === 0) {
    return <p className={styles.emptyMessage}>{emptyMessage}</p>;
  }

  return (
    <div className={styles.accordion}>
      {items.map((item, index) => (
        <details key={item.id} className={styles.accordionItem} open={index === 0}>
          <summary className={styles.accordionHeader}>{item.header}</summary>
          <div className={styles.accordionBody}>{item.content}</div>
        </details>
      ))}
    </div>
  );
};
