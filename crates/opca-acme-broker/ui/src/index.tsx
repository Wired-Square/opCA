import "@wired-square/kit/theme.css";
import "./theme.css";
import "@wired-square/kit/kit.css";
import "./page.css";

import { render } from "solid-js/web";

import { App } from "./App";

const root = document.getElementById("root");
if (!root) throw new Error("index.html has no #root to render into");
render(() => <App />, root);
