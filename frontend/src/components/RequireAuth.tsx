import { Outlet, Navigate, useLocation } from "react-router-dom";
import { isAuthed } from "../lib/auth";

export default function RequireAuth() {
  const loc = useLocation();
  const authed = isAuthed(); // reads localStorage
  if (!authed) {
    return <Navigate to="/login" replace state={{ from: loc }} />;
  }
  return <Outlet />;
}
