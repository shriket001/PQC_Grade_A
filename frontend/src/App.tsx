import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router-dom";

import { AuthBootstrap } from "@/components/AuthBootstrap";
import { RequireAuth } from "@/components/RequireAuth";

// Lazy-load each page so the initial bundle is just the auth shell + router.
const Register = lazy(() => import("@/pages/Register"));
const Login = lazy(() => import("@/pages/Login"));
const VerifyEmail = lazy(() => import("@/pages/VerifyEmail"));
const Conversations = lazy(() => import("@/pages/Conversations"));

export default function App(): JSX.Element {
  return (
    <AuthBootstrap>
      <Suspense fallback={null}>
        <Routes>
          <Route path="/register" element={<Register />} />
          <Route path="/login" element={<Login />} />
          <Route path="/verify-email" element={<VerifyEmail />} />
          <Route
            path="/"
            element={
              <RequireAuth>
                <Conversations />
              </RequireAuth>
            }
          />
          <Route path="*" element={<Register />} />
        </Routes>
      </Suspense>
    </AuthBootstrap>
  );
}
