import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './FileUpload.css';
import { useNavigate } from 'react-router-dom';

const FileUpload: React.FC = () =>{
  const [file, setFile] = useState<File | null>(null);
  const [uploadMessage, setUploadMessage] = useState('');
  const [filename, setFilename] = useState('');
  const [analysisResult, setAnalysisResult] = useState<any>(null);
  const [dbLogs, setDbLogs] = useState<any[]>([]);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);
  const navigate = useNavigate();
  const [fileError, setFileError] = useState('');

  // Check if user is authenticated
  useEffect(() => {
  const checkAuth = async () => {
    try 
    {
      const res = await axios.get('https://log-analyzer-9z9j.onrender.com/check-auth', {
        withCredentials: true
      });
      console.log(res.data);
      if (res.data.loggedIn) {
        setIsAuthenticated(true);
      }
    } 
    catch (err) 
    {
      console.log(err);
      setIsAuthenticated(false);
    }
  };
  checkAuth();
}, []);


  // Show loading while checking authentication
  if (isAuthenticated === null) 
  {
    return <div>Checking authentication...</div>;
  }

  // Redirect if user not logged in
  if (isAuthenticated === false) 
  {
    navigate('/');
    return null;
  }

  // Checking if the uploaded file is in txt format
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
  if (e.target.files && e.target.files.length > 0)
  {
    const selectedFile = e.target.files[0];
    const fileName = selectedFile.name;
    if (!fileName.toLowerCase().endsWith('.txt')) 
    {
      setFile(null);
      setFileError('Please upload a file in .txt format');
    } 
    else 
    {
      setFile(selectedFile);
      setFileError('');
    }
  }
  
  // Uploading the file
  const handleUpload = async () => {
    if (!file) return;
    const formData = new FormData();
    formData.append('file', file);
    try 
    {
      const response = await axios.post('https://log-analyzer-9z9j.onrender.com/upload', formData, { withCredentials: true });
      setUploadMessage(response.data.message);
      setFilename(response.data.filename);
    } 
    catch (error: any) 
    {
      setUploadMessage(error.response?.data?.message || 'Upload failed');
    }
  };

  // Used to call the /analyze-zscaler API endpoint 
  const handleAnalyze = async () => {
    if (!filename) return;

    try 
    {
      const response = await axios.post('https://log-analyzer-9z9j.onrender.com/analyze-zscaler', { filename }, { withCredentials: true });
      setAnalysisResult(response.data);
    } 
    catch (error: any) 
    {
      alert('Analysis failed: ' + (error.response?.data?.error || 'Unknown error'));
    }
  };

  // Used to call /analyze-db-logs endpoint
  const handleDbAnalyze = async () => {
    try 
    {
      const response = await axios.get('https://log-analyzer-9z9j.onrender.com/analyze-db-logs', { withCredentials: true });
      setDbLogs(response.data);
    } 
    catch (error: any) 
    {
      alert('DB log analysis failed: ' + (error.response?.data?.error || 'Unknown error'));
    }
  };
  
    // Logout functionality
    const handleLogout = async () => {
    try 
    {
      await axios.post('https://log-analyzer-9z9j.onrender.com/logout', {}, { withCredentials: true });
      setIsAuthenticated(false);
      navigate('/');
    } 
    catch (error) 
    {
      console.error('Logout failed', error);
    }
};

  return (
    <div className="upload-container">
       <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button onClick={handleLogout}>Logout</button>
      </div>
      <h2>Upload a Log File</h2>
      <input type="file" onChange={handleFileChange} />
      <button onClick={handleUpload}>Upload</button>
      <p>{uploadMessage}</p>
      {
        filename && 
        (
          <div>
            <button onClick={handleAnalyze}>Analyze File</button>
          </div>
        )
      }

      <div>
        <button onClick={handleDbAnalyze}>View past events that were blocked</button>
      </div>
      {
      analysisResult && 
      (
        <div className="analysis-result">
          <h3>Analysis Summary</h3>
          <div className="summary-cards">
          <div className="card">
            <h4>Total Events</h4>
            <p>{analysisResult.summary?.total_events}</p>
          </div>
          <div className="card">
            <h4>Total Threats</h4>
            <p>{analysisResult.summary?.total_threats}</p>
          </div>
        </div>

        <div className="top-threats">
          <h4>Top Threats</h4>
          <ul>
            {
              Object.entries(analysisResult.summary?.top_threats || {}).map(([threatType, count]: any, index) =>(
              <li key={index}>
                <span className="threat-type">{threatType}</span>: <span className="threat-count">{count}</span>
              </li>
              )
              )
            }
          </ul>
        </div>

    <h4>Blocked Threats</h4>
    <table className="threat-table">
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>User</th>
          <th>URL</th>
          <th>Threat</th>
        </tr>
      </thead>
      <tbody>
        {analysisResult.blocked_threats.map((threat: any, index: number) => (
          <tr key={index}>
            <td>{threat.timestamp}</td>
            <td>{threat.user}</td>
            <td>{threat.url}</td>
            <td>{threat.threat}</td>
          </tr>
        ))}
      </tbody>
    </table>

    {analysisResult.note && <p className="note"><strong>Note:</strong> {analysisResult.note}</p>}
  </div>
)}{dbLogs.length > 0 && (
  <div>
    <h3>Previous log events that were blocked</h3>
    <table border = {1} cellPadding= {8} cellSpacing={0}>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>URL</th>
          <th>Source IP</th>
          <th>Threat</th>
        </tr>
      </thead>
      <tbody>
        {dbLogs.map((log, index) => (
          <tr key={index}>
            <td>{log.timestamp}</td>
            <td>{log.url}</td>
            <td>{log.source_ip}</td>
            <td>{log.threat}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
  
)}
</div>
);
};

export default FileUpload;
