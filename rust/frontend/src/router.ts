import { lazy } from "solid-js";
import type { RouteDefinition } from "@solidjs/router";

const Connect = lazy(() => import("./pages/Connect"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
const CA = lazy(() => import("./pages/CA"));
const Certs = lazy(() => import("./pages/Certs"));
const CertCreate = lazy(() => import("./pages/CertCreate"));
const CertImport = lazy(() => import("./pages/CertImport"));
const CertInfo = lazy(() => import("./pages/CertInfo"));
const CRL = lazy(() => import("./pages/CRL"));
const DKIM = lazy(() => import("./pages/DKIM"));
const OpenVPN = lazy(() => import("./pages/OpenVPN"));
const Database = lazy(() => import("./pages/Database"));

export const routes: RouteDefinition[] = [
  { path: "/", component: Connect },
  { path: "/dashboard", component: Dashboard },
  { path: "/ca", component: CA },
  { path: "/certs", component: Certs },
  { path: "/certs/create", component: CertCreate },
  { path: "/certs/import", component: CertImport },
  { path: "/certs/:serial", component: CertInfo },
  { path: "/crl", component: CRL },
  { path: "/csr", component: lazy(() => import("./pages/CSR")) },
  { path: "/dkim", component: DKIM },
  { path: "/openvpn", component: OpenVPN },
  { path: "/database", component: Database },
  { path: "/vault", component: lazy(() => import("./pages/Vault")) },
  { path: "/log", component: lazy(() => import("./pages/Log")) },
];
