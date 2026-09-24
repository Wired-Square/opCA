import { useLocation } from "@solidjs/router";

export default function Placeholder() {
  const location = useLocation();
  const title = () => {
    const path = location.pathname.slice(1);
    return path.charAt(0).toUpperCase() + path.slice(1);
  };

  return (
    <div class="p-4">
      <h2>{title()}</h2>
      <p class="text-muted mt-2">
        Coming soon
      </p>
    </div>
  );
}
