import { BrowserRouter, Route, Routes } from 'react-router-dom'
import Navbar from './components/Navbar.jsx'
import FindingDetail from './pages/FindingDetail.jsx'
import ProgressPage from './pages/ProgressPage.jsx'
import ResultsPage from './pages/ResultsPage.jsx'
import ScanPage from './pages/ScanPage.jsx'

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-50">
        <Navbar />
        <main className="max-w-5xl mx-auto px-4 py-8">
          <Routes>
            <Route path="/" element={<ScanPage />} />
            <Route path="/scan/:id/progress" element={<ProgressPage />} />
            <Route path="/scan/:id/results" element={<ResultsPage />} />
            <Route path="/scan/:id/findings/:fid" element={<FindingDetail />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
