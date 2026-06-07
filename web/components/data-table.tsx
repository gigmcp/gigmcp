"use client";
import * as React from "react";
import { useTranslations } from "next-intl";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export interface Column<T> {
  header: string;
  cell: (row: T) => React.ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  getKey?: (row: T, index: number) => string | number;
}

export function DataTable<T>({
  columns,
  data,
  getKey = (_row, index) => index,
}: DataTableProps<T>) {
  const t = useTranslations("common");
  return (
    <Table>
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          {columns.map((col) => (
            <TableHead key={col.header}>{col.header}</TableHead>
          ))}
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.length === 0 ? (
          <TableRow className="hover:bg-transparent">
            <TableCell
              colSpan={columns.length}
              className="py-10 text-center text-muted-foreground"
            >
              {t("table.empty")}
            </TableCell>
          </TableRow>
        ) : (
          data.map((row, i) => (
            <TableRow key={getKey(row, i)}>
              {columns.map((col) => (
                <TableCell key={col.header}>{col.cell(row)}</TableCell>
              ))}
            </TableRow>
          ))
        )}
      </TableBody>
    </Table>
  );
}
