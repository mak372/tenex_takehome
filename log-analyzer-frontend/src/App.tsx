import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Auth from './pages/Auth';
import FileUpload from './pages/FileUpload';

const App: React.FC = () => {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Auth />} />
        <Route path="/upload" element={<FileUpload />} />
      </Routes>
    </Router>
  );
};

export default App;
