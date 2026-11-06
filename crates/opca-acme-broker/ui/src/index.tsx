import "@wired-square/kit/theme.css";
import "./theme.css";
import "@wired-square/kit/kit.css";
import "@wired-square/appliance-ui/shell.css";
import "./page.css";

import { Chrome, Shell } from "@wired-square/appliance-ui";
import { render } from "solid-js/web";

import { App } from "./App";

const root = document.getElementById("root");
if (!root) throw new Error("index.html has no #root to render into");
render(
  () => (
    <Shell>
      <Chrome>
        <App />
      </Chrome>
    </Shell>
  ),
  root,
);
