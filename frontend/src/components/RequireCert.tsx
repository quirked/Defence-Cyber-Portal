import { Outlet, Navigate } from "react-router-dom";
import { isCert, isAuthed } from "../lib/auth";

export default function RequireCert() {
  if (!isAuthed()) return <Navigate to="/login" replace />;
  if (!isCert())   return <Navigate to="/dashboard" replace />;
  return <Outlet />;
}
