import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import LandingPage from "./LandingPage";
import DashboardPage from "./DashboardPage";

export default function App() {
  return (
    <Router>

      <Routes>

        <Route path="/" element={<LandingPage />} />

        <Route path="/app" element={<DashboardPage />} />

      </Routes>

    </Router>
  );
}