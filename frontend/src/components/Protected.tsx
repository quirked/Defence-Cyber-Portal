import { Navigate } from "react-router-dom";
import { isAuthed } from "../lib/auth";

export default function Protected({ children }: { children: JSX.Element }) {
  return isAuthed() ? children : <Navigate to="/login" replace />;
}
