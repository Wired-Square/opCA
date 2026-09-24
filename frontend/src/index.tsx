/* @refresh reload */
import { render } from "solid-js/web";
import { Router, Route } from "@solidjs/router";
import App from "./App";
import { routes } from "./router";
// Fonts (self-hosted via @fontsource)
import "@fontsource/dm-sans/400.css";
import "@fontsource/dm-sans/400-italic.css";
import "@fontsource/dm-sans/500.css";
import "@fontsource/dm-sans/600.css";
import "@fontsource/dm-sans/700.css";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "@fontsource/jetbrains-mono/600.css";
import "@fontsource/jetbrains-mono/700.css";
import "@fontsource/ubuntu/400.css";
import "@fontsource/ubuntu/500.css";
import "@fontsource/ubuntu/700.css";
import "./styles/global.css";
// Initialise theme on load
import "./stores/theme";

const root = document.getElementById("root");

render(
  () => (
    <Router root={App}>
      {routes.map((r) => (
        <Route path={r.path} component={r.component} />
      ))}
    </Router>
  ),
  root!,
);
