import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout/Layout'
import Overview from './pages/Overview'
import ThreatHunt from './pages/ThreatHunt'
import FlowInvestigation from './pages/FlowInvestigation'
import TLSIntelligence from './pages/TLSIntelligence'
import FingerprintExplorer from './pages/FingerprintExplorer'
import Experiments from './pages/Experiments'
import Models from './pages/Models'
import Explainability from './pages/Explainability'
import DatasetExplorer from './pages/DatasetExplorer'
import ResearchView from './pages/ResearchView'
import LiveStream from './pages/LiveStream'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/overview" replace />} />
          <Route path="overview" element={<Overview />} />
          <Route path="threat-hunt" element={<ThreatHunt />} />
          <Route path="live" element={<LiveStream />} />
          <Route path="flows/:flowId" element={<FlowInvestigation />} />
          <Route path="tls" element={<TLSIntelligence />} />
          <Route path="fingerprints" element={<FingerprintExplorer />} />
          <Route path="fingerprints/:type/:hash" element={<FingerprintExplorer />} />
          <Route path="experiments" element={<Experiments />} />
          <Route path="experiments/:experimentId" element={<Experiments />} />
          <Route path="models" element={<Models />} />
          <Route path="models/:modelId" element={<Models />} />
          <Route path="explainability" element={<Explainability />} />
          <Route path="datasets" element={<DatasetExplorer />} />
          <Route path="datasets/:datasetId" element={<DatasetExplorer />} />
          <Route path="research" element={<ResearchView />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}