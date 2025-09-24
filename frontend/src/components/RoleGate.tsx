import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function RoleGate({ allow, children }: { allow: string; children: React.ReactNode }) {
  const { user } = useAuth();
  if (!user) return null;
  if (user.role !== allow) return <Navigate to="/" replace />;
  return <>{children}</>;
}
