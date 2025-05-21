import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import { jwtDecode } from 'jwt-decode';
import {
  Container, // ThemeProvider, createTheme, CssBaseline, GlobalStyles removed
  Paper, Box, Typography, Grid, Chip, Stack,
  CircularProgress, InputAdornment, IconButton, LinearProgress 
} from '@mui/material';
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Home as HomeIcon, Work as WorkIcon, Chat as ChatIcon,
  Person as PersonIcon, Add as AddIcon, // LogoutIcon removed
  Upload, Delete, InsertDriveFile
} from '@mui/icons-material';
import { LogOut } from 'lucide-react'; // Added for shadcn/ui compatible logout icon
import { BrowserRouter, Routes, Route, useNavigate, useParams } from 'react-router-dom';
import axios from 'axios';
import io from 'socket.io-client';
import { loadStripe } from '@stripe/stripe-js';
import { Elements, CardElement, useStripe, useElements } from '@stripe/react-stripe-js';

// Constants
const API_URL = 'http://localhost:5000/api';
const SOCKET_URL = 'http://localhost:5000';
const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2MB
const TOTAL_MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const STRIPE_PUBLIC_KEY = 'pk_test_51QtvtL027UxUfugRCZf2rPjYijwIqCRxggXvfCOzjeoYBbpCgZ2woxJYdJAP6F3I5e4s8tcMW2VJTwqlwTIYWLXu00GPcShZl5';

// Initialize axios instance
const api = axios.create({ 
  baseURL: API_URL,
  timeout: 10000
});

// Initialize Stripe
const stripePromise = loadStripe(STRIPE_PUBLIC_KEY);

// Auth Context
const AuthContext = createContext(null);

// Error Boundary Component
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <Container>
          <div className="p-4 mt-2 bg-red-100 text-red-700 rounded-md">
            <h3 className="font-bold">Error</h3>
            <p>Something went wrong. Please refresh the page or try again later.</p>
          </div>
        </Container>
      );
    }
    return this.props.children;
  }
}

// Auth Provider Component
const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [tokenExpiry, setTokenExpiry] = useState(null);
  const tokenCheckInterval = useRef(null);

  const checkTokenExpiry = useCallback(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      setUser(null);
      return false;
    }

    try {
      const decoded = jwtDecode(token);
      const expiryTime = decoded.exp * 1000;
      setTokenExpiry(expiryTime);
      
      if (Date.now() >= expiryTime) {
        logout();
        return false;
      }
      return true;
    } catch (error) {
      console.error('Token decode error:', error);
      logout();
      return false;
    }
  }, []);

  useEffect(() => {
    const initAuth = () => {
      const token = localStorage.getItem('token');
      const storedUser = localStorage.getItem('user');
      
      if (token && storedUser && checkTokenExpiry()) {
        setUser(JSON.parse(storedUser));
        api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      }
      setLoading(false);
    };

    initAuth();
    tokenCheckInterval.current = setInterval(checkTokenExpiry, 60000);
    
    return () => {
      if (tokenCheckInterval.current) {
        clearInterval(tokenCheckInterval.current);
      }
    };
  }, [checkTokenExpiry]);

  const login = async (values) => {
    try {
      const { data } = await api.post('/auth/login', values);
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
      setUser(data.user);
      checkTokenExpiry();
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.message || 'Login failed'
      };
    }
  };

  const register = async (values) => {
    try {
      const { data } = await api.post('/auth/register', values);
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
      setUser(data.user);
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.message || 'Registration failed'
      };
    }
  };

  const logout = useCallback(() => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    delete api.defaults.headers.common['Authorization'];
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, login, register, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook for auth
const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// RegisterPage Component
const RegisterPage = () => {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [values, setValues] = useState({
    username: '',
    email: '',
    password: '',
    role: ''
  });
  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  const validate = () => {
    const newErrors = {};
    const emailRegex = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;

    if (!values.username) {
      newErrors.username = 'Username is required';
    } else if (values.username.length < 3) {
      newErrors.username = 'Username must be at least 3 characters';
    }

    if (!values.email) {
      newErrors.email = 'Email is required';
    } else if (!emailRegex.test(values.email)) {
      newErrors.email = 'Invalid email address';
    }

    if (!values.password) {
      newErrors.password = 'Password is required';
    } else if (values.password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }

    if (!values.role) {
      newErrors.role = 'Role is required';
    } else if (!['client', 'freelancer'].includes(values.role.toLowerCase())) {
      newErrors.role = 'Role must be either client or freelancer. Please enter "client" or "freelancer".';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setValues(prev => ({ ...prev, [name]: value }));
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validate() || isSubmitting) return;

    setIsSubmitting(true);
    try {
      const result = await register({
        ...values,
        role: values.role.toLowerCase()
      });
      if (result.success) {
        navigate('/');
      } else {
        setErrors(prev => ({ ...prev, submit: result.error }));
      }
    } catch (error) {
      setErrors(prev => ({
        ...prev,
        submit: 'An unexpected error occurred. Please try again.'
      }));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <div className="p-8 bg-white rounded-lg shadow-md w-full max-w-md">
        <h2 className="text-2xl font-bold text-center mb-6">Create Account</h2>
        {errors.submit && (
          <Alert variant="destructive" className="mb-4">
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>
              {errors.submit}
            </AlertDescription>
          </Alert>
        )}
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              name="username"
              value={values.username}
              onChange={handleChange}
              placeholder="Your username"
              className={errors.username ? 'border-red-500' : ''}
              autoComplete="username"
              autoFocus
            />
            {errors.username && <p className="text-red-500 text-sm mt-1">{errors.username}</p>}
          </div>
          <div>
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              name="email"
              type="email"
              value={values.email}
              onChange={handleChange}
              placeholder="your.email@example.com"
              className={errors.email ? 'border-red-500' : ''}
              autoComplete="email"
            />
            {errors.email && <p className="text-red-500 text-sm mt-1">{errors.email}</p>}
          </div>
          <div>
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              name="password"
              type="password"
              value={values.password}
              onChange={handleChange}
              placeholder="••••••••"
              className={errors.password ? 'border-red-500' : ''}
              autoComplete="new-password"
            />
            {errors.password && <p className="text-red-500 text-sm mt-1">{errors.password}</p>}
          </div>
          <div>
            <Label htmlFor="role">Role (client/freelancer)</Label>
            <Input
              id="role"
              name="role"
              value={values.role}
              onChange={handleChange}
              placeholder="Enter 'client' or 'freelancer'"
              className={errors.role ? 'border-red-500' : ''}
            />
            {errors.role && <p className="text-red-500 text-sm mt-1">{errors.role}</p>}
          </div>
          <Button type="submit" className="w-full" disabled={isSubmitting}>
            {isSubmitting ? 'Creating Account...' : 'Create Account'}
          </Button>
          <Button 
            variant="link" 
            onClick={() => navigate('/login')} 
            className="w-full"
            disabled={isSubmitting}
          >
            Already have an account? Login
          </Button>
        </form>
      </div>
    </div>
  );
};

// Protected Route Component
const ProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!loading && !user) {
      navigate('/login');
    }
  }, [user, loading, navigate]);

  if (loading) {
    return <CircularProgress />;
  }

  return children;
};

// Login Page Component
const LoginPage = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [values, setValues] = useState({ email: '', password: '' });
  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  const validate = () => {
    const newErrors = {};
    const emailRegex = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;
    
    if (!values.email) {
      newErrors.email = 'Email is required';
    } else if (!emailRegex.test(values.email)) {
      newErrors.email = 'Invalid email address';
    }

    if (!values.password) {
      newErrors.password = 'Password is required';
    } else if (values.password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setValues(prev => ({ ...prev, [name]: value }));
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validate() || isSubmitting) return;

    setIsSubmitting(true);
    try {
      const result = await login(values);
      if (result.success) {
        navigate('/');
      } else {
        setErrors(prev => ({ ...prev, submit: result.error }));
      }
    } catch (error) {
      setErrors(prev => ({
        ...prev,
        submit: 'An unexpected error occurred. Please try again.'
      }));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <div className="p-8 bg-white rounded-lg shadow-md w-full max-w-md">
        <h2 className="text-2xl font-bold text-center mb-6">Welcome Back</h2>
        {errors.submit && (
          <Alert variant="destructive" className="mb-4">
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>
              {errors.submit}
            </AlertDescription>
          </Alert>
        )}
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              name="email"
              type="email"
              value={values.email}
              onChange={handleChange}
              placeholder="your.email@example.com"
              className={errors.email ? 'border-red-500' : ''}
              autoComplete="email"
              autoFocus
            />
            {errors.email && <p className="text-red-500 text-sm mt-1">{errors.email}</p>}
          </div>
          <div>
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              name="password"
              type="password"
              value={values.password}
              onChange={handleChange}
              placeholder="••••••••"
              className={errors.password ? 'border-red-500' : ''}
              autoComplete="current-password"
            />
            {errors.password && <p className="text-red-500 text-sm mt-1">{errors.password}</p>}
          </div>
          <Button type="submit" className="w-full" disabled={isSubmitting}>
            {isSubmitting ? 'Signing In...' : 'Sign In'}
          </Button>
          <Button 
            variant="link" 
            onClick={() => navigate('/register')} 
            className="w-full"
            disabled={isSubmitting}
          >
            Don't have an account? Register
          </Button>
        </form>
      </div>
    </div>
  );
};

// ProjectsList Component
const ProjectsList = () => {
  const [projects, setProjects] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const { user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    loadProjects();
  }, []);

  const loadProjects = async () => {
    try {
      setIsLoading(true);
      const { data } = await api.get('/projects');
      setProjects(data.projects);
    } catch (error) {
      console.error('Failed to load projects:', error);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '70vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Container>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4">Projects</Typography>
        {user?.role === 'client' && (
          <Button 
            variant="contained" 
            startIcon={<AddIcon />} 
            onClick={() => navigate('/create-project')}
          >
            Create Project
          </Button>
        )}
      </Box>
      <Grid container spacing={3}>
        {projects.map((project) => (
          <Grid item xs={12} sm={6} md={4} key={project._id}>
            <Paper elevation={3} sx={{ p: 2 }}>
              <Typography variant="h6">{project.title}</Typography>
              <Typography variant="body2" sx={{ mt: 1, height: 48, overflow: 'hidden' }}>
                {project.description}
              </Typography>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 2 }}>
                <Chip 
                  label={project.status} 
                  color={
                    project.status === 'open' ? 'primary' :
                    project.status === 'in-progress' ? 'warning' :
                    'success'
                  } 
                  size="small" 
                />
                <Typography variant="subtitle1">${project.budget}</Typography>
              </Box>
              <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
                {project.skills.slice(0, 3).map((skill, index) => (
                  <Chip key={index} label={skill} size="small" variant="outlined" />
                ))}
                {project.skills.length > 3 && (
                  <Chip label={`+${project.skills.length - 3}`} size="small" variant="outlined" />
                )}
              </Stack>
              <Button 
                variant="outlined" 
                fullWidth 
                sx={{ mt: 2 }} 
                onClick={() => navigate(`/projects/${project._id}`)}
              >
                View Details
              </Button>
            </Paper>
          </Grid>
        ))}
      </Grid>
    </Container>
  );
};

// ProjectDetails Component
const ProjectDetails = () => {
  const [project, setProject] = useState(null);
  const [proposals, setProposals] = useState([]);
  const [proposalModal, setProposalModal] = useState(false);
  const [paymentModal, setPaymentModal] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const { user } = useAuth();
  const { id } = useParams();
  const navigate = useNavigate();

  const [proposalValues, setProposalValues] = useState({
    coverLetter: '',
    bidAmount: '',
    estimatedDuration: ''
  });

  const [proposalErrors, setProposalErrors] = useState({});

  useEffect(() => {
    loadProject();
    if (user?.role === 'client') {
      loadProposals();
    }
  }, [id, user]);

  const loadProject = async () => {
    try {
      setIsLoading(true);
      const { data } = await api.get(`/projects/${id}`);
      setProject(data);
    } catch (error) {
      console.error('Failed to load project:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const loadProposals = async () => {
    try {
      const { data } = await api.get(`/projects/${id}/proposals`);
      setProposals(data);
    } catch (error) {
      console.error('Failed to load proposals:', error);
    }
  };

  const validateProposal = () => {
    const errors = {};
    if (!proposalValues.coverLetter) {
      errors.coverLetter = 'Cover letter is required';
    }
    if (!proposalValues.bidAmount || proposalValues.bidAmount <= 0) {
      errors.bidAmount = 'Valid bid amount is required';
    }
    if (!proposalValues.estimatedDuration || proposalValues.estimatedDuration <= 0) {
      errors.estimatedDuration = 'Valid duration is required';
    }
    setProposalErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const submitProposal = async (e) => {
    e.preventDefault();
    if (!validateProposal()) return;

    try {
      await api.post('/proposals', {
        projectId: id,
        ...proposalValues,
        bidAmount: Number(proposalValues.bidAmount),
        estimatedDuration: Number(proposalValues.estimatedDuration)
      });
      await api.post('/chats', { recipientId: project.client._id, projectId: project._id });
      setProposalModal(false);
      
      // Optionally reload project to show updated status
      loadProject();
    } catch (error) {
      setProposalErrors({ submit: 'Failed to submit proposal' });
    }
  };

  const acceptProposal = async (proposalId) => {
    try {
      await api.patch(`/proposals/${proposalId}`, { status: 'accepted' });
      loadProject();
      loadProposals();
    } catch (error) {
      console.error('Failed to accept proposal:', error);
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '70vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!project) {
    return (
      <div className="p-4 bg-red-100 text-red-700 rounded-md">Project not found</div>
    );
  }

  return (
    <Container>
      <Paper elevation={3} sx={{ p: 4, mb: 4 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h4">{project.title}</Typography>
          <Chip 
            label={project.status} 
            color={
              project.status === 'open' ? 'primary' :
              project.status === 'in-progress' ? 'warning' :
              'success'
            }
          />
        </Box>
        
        <Typography variant="body1" sx={{ mb: 3 }}>
          {project.description}
        </Typography>

        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6}>
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle1" color="text.secondary">Budget</Typography>
              <Typography variant="h6">${project.budget}</Typography>
            </Box>
            <Box>
              <Typography variant="subtitle1" color="text.secondary">Posted By</Typography>
              <Typography variant="h6">{project.client.username}</Typography>
            </Box>
          </Grid>
          <Grid item xs={12} sm={6}>
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle1" color="text.secondary">Deadline</Typography>
              <Typography variant="h6">
                {project.deadline ? new Date(project.deadline).toLocaleDateString() : 'Not specified'}
              </Typography>
            </Box>
            <Box>
              <Typography variant="subtitle1" color="text.secondary">Required Skills</Typography>
              <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
                {project.skills.map((skill, index) => (
                  <Chip key={index} label={skill} />
                ))}
              </Stack>
            </Box>
          </Grid>
        </Grid>

        {user?.role === 'freelancer' && project.status === 'open' && (
          <Button variant="contained" onClick={() => setProposalModal(true)}>
            Submit Proposal
          </Button>
        )}

        {user?.role === 'client' && project.status === 'in-progress' && (
          <Button variant="contained" onClick={() => setPaymentModal(true)}>
            Make Payment
          </Button>
        )}
      </Paper>

      {/* Proposals Section for Clients */}
      {user?.role === 'client' && proposals.length > 0 && (
        <Box sx={{ mt: 4 }}>
          <Typography variant="h5" gutterBottom>
            Proposals ({proposals.length})
          </Typography>
          <Stack spacing={2}>
            {proposals.map((proposal) => (
              <Paper key={proposal._id} elevation={1} sx={{ p: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                  <Typography variant="subtitle1">
                    {proposal.freelancer.username}
                  </Typography>
                  <Chip label={proposal.status} />
                </Box>
                <Typography variant="body1" sx={{ mb: 2 }}>
                  {proposal.coverLetter}
                </Typography>
                <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                  <Typography variant="body2">
                    Bid Amount: ${proposal.bidAmount}
                  </Typography>
                  <Typography variant="body2">
                    Duration: {proposal.estimatedDuration} days
                  </Typography>
                </Box>
                {proposal.status === 'pending' && (
                  <Button 
                    variant="outlined" 
                    onClick={() => acceptProposal(proposal._id)}
                  >
                    Accept Proposal
                  </Button>
                )}
              </Paper>
            ))}
          </Stack>
        </Box>
      )}

      {/* Submit Proposal Modal */}
      <Drawer
        anchor="bottom"
        open={proposalModal}
        onClose={() => setProposalModal(false)}
      >
        <Box sx={{ p: 3 }}>
          <Typography variant="h5" gutterBottom>Submit Proposal</Typography>
          {proposalErrors.submit && (
            <div className="mb-4 p-3 bg-red-100 text-red-700 rounded">
              {proposalErrors.submit}
            </div>
          )}
          <Box component="form" onSubmit={submitProposal}>
            <Stack spacing={2}>
              <TextField
                label="Cover Letter"
                name="coverLetter"
                value={proposalValues.coverLetter}
                onChange={(e) => setProposalValues({ 
                  ...proposalValues, 
                  coverLetter: e.target.value 
                })}
                multiline
                rows={4}
                error={!!proposalErrors.coverLetter}
                helperText={proposalErrors.coverLetter}
                fullWidth
              />
              <TextField
                label="Bid Amount ($)"
                name="bidAmount"
                type="number"
                value={proposalValues.bidAmount}
                onChange={(e) => setProposalValues({ 
                  ...proposalValues, 
                  bidAmount: e.target.value 
                })}
                error={!!proposalErrors.bidAmount}
                helperText={proposalErrors.bidAmount}
                fullWidth
              />
              <TextField
                label="Estimated Duration (days)"
                name="estimatedDuration"
                type="number"
                value={proposalValues.estimatedDuration}
                onChange={(e) => setProposalValues({ 
                  ...proposalValues, 
                  estimatedDuration: e.target.value 
                })}
                error={!!proposalErrors.estimatedDuration}
                helperText={proposalErrors.estimatedDuration}
                fullWidth
              />
              <Button variant="contained" type="submit">
                Submit Proposal
              </Button>
            </Stack>
          </Box>
        </Box>
      </Drawer>

      {/* Payment Modal */}
      <Drawer
        anchor="bottom"
        open={paymentModal}
        onClose={() => setPaymentModal(false)}
      >
        <Box sx={{ p: 3 }}>
          <Typography variant="h5" gutterBottom>Complete Payment</Typography>
          <Elements stripe={stripePromise}>
            <PaymentForm 
              projectId={id} 
              onSuccess={() => {
                setPaymentModal(false);
                loadProject();
              }} 
            />
          </Elements>
        </Box>
      </Drawer>
    </Container>
  );
};

// CreateProject Component
const CreateProject = () => {
  const [values, setValues] = useState({
    title: '',
    description: '',
    budget: '',
    skills: '',
    deadline: '',
    attachments: []
  });
  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const navigate = useNavigate();
  const fileInputRef = useRef();

  const validateForm = () => {
    const newErrors = {};

    if (!values.title.trim()) {
      newErrors.title = 'Title is required';
    }

    if (!values.description.trim()) {
      newErrors.description = 'Description is required';
    } else if (values.description.length < 50) {
      newErrors.description = 'Description must be at least 50 characters';
    }

    if (!values.budget || isNaN(values.budget) || Number(values.budget) <= 0) {
      newErrors.budget = 'Budget must be a positive number';
    }

    if (!values.skills.trim()) {
      newErrors.skills = 'At least one skill is required';
    }

    if (values.deadline) {
      const deadlineDate = new Date(values.deadline);
      if (deadlineDate <= new Date()) {
        newErrors.deadline = 'Deadline must be in the future';
      }
    }

    const totalFileSize = values.attachments.reduce((sum, file) => sum + file.size, 0);
    if (totalFileSize > TOTAL_MAX_FILE_SIZE) {
      newErrors.attachments = 'Total file size cannot exceed 10MB';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleFileChange = (event) => {
    const files = Array.from(event.target.files);
    const validFiles = files.filter(file => {
      const isValid = file.size <= MAX_FILE_SIZE;
      if (!isValid) {
        alert(`File ${file.name} is too large. Maximum size is 2MB`);
      }
      return isValid;
    });

    setValues(prev => ({
      ...prev,
      attachments: [...prev.attachments, ...validFiles]
    }));
  }
    // Continuing CreateProject component...
  const removeFile = (index) => {
    setValues(prev => ({
      ...prev,
      attachments: prev.attachments.filter((_, i) => i !== index)
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validateForm() || isSubmitting) return;

    setIsSubmitting(true);
    setUploadProgress(0);

    try {
      const formData = new FormData();
      formData.append('title', values.title.trim());
      formData.append('description', values.description.trim());
      formData.append('budget', Number(values.budget));
      formData.append('skills', JSON.stringify(
        values.skills.split(',').map(s => s.trim()).filter(Boolean)
      ));
      
      if (values.deadline) {
        formData.append('deadline', values.deadline);
      }

      // Handle file uploads
      values.attachments.forEach(file => {
        formData.append('attachments', file);
      });

      await api.post('/projects', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        onUploadProgress: (progressEvent) => {
          const progress = (progressEvent.loaded / progressEvent.total) * 100;
          setUploadProgress(Math.round(progress));
        }
      });

      navigate('/projects');
    } catch (error) {
      setErrors(prev => ({
        ...prev,
        submit: error.response?.data?.message || 'Failed to create project'
      }));
    } finally {
      setIsSubmitting(false);
      setUploadProgress(0);
    }
  };

  return (
    <Container maxWidth="md">
      <Paper elevation={3} sx={{ p: 4, my: 4 }}>
        <Typography variant="h4" gutterBottom>
          Create New Project
        </Typography>

        {errors.submit && (
          <div className="mb-4 p-3 bg-red-100 text-red-700 rounded">
            {errors.submit}
          </div>
        )}

        <Box component="form" onSubmit={handleSubmit}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <TextField
                label="Project Title"
                name="title"
                value={values.title}
                onChange={(e) => setValues({ ...values, title: e.target.value })}
                error={!!errors.title}
                helperText={errors.title}
                fullWidth
                required
              />
            </Grid>

            <Grid item xs={12}>
              <TextField
                label="Project Description"
                name="description"
                value={values.description}
                onChange={(e) => setValues({ ...values, description: e.target.value })}
                error={!!errors.description}
                helperText={errors.description}
                fullWidth
                required
                multiline
                rows={4}
              />
            </Grid>

            <Grid item xs={12} sm={6}>
              <TextField
                label="Budget ($)"
                name="budget"
                type="number"
                value={values.budget}
                onChange={(e) => setValues({ ...values, budget: e.target.value })}
                error={!!errors.budget}
                helperText={errors.budget}
                fullWidth
                required
                InputProps={{
                  startAdornment: <InputAdornment position="start">$</InputAdornment>,
                }}
              />
            </Grid>

            <Grid item xs={12} sm={6}>
              <TextField
                label="Deadline"
                name="deadline"
                type="date"
                value={values.deadline}
                onChange={(e) => setValues({ ...values, deadline: e.target.value })}
                error={!!errors.deadline}
                helperText={errors.deadline}
                fullWidth
                InputLabelProps={{ shrink: true }}
              />
            </Grid>

            <Grid item xs={12}>
              <TextField
                label="Required Skills (comma-separated)"
                name="skills"
                value={values.skills}
                onChange={(e) => setValues({ ...values, skills: e.target.value })}
                error={!!errors.skills}
                helperText={errors.skills || "Enter skills separated by commas (e.g., React, Node.js, MongoDB)"}
                fullWidth
                required
              />
            </Grid>

            <Grid item xs={12}>
              <input
                type="file"
                multiple
                onChange={handleFileChange}
                style={{ display: 'none' }}
                ref={fileInputRef}
                accept=".pdf,.doc,.docx,.txt,.jpg,.jpeg,.png"
              />
              <Button
                variant="outlined"
                onClick={() => fileInputRef.current.click()}
                startIcon={<Upload />}
                fullWidth
              >
                Upload Files
              </Button>
              
              {errors.attachments && (
                <Typography color="error" variant="caption" display="block" sx={{ mt: 1 }}>
                  {errors.attachments}
                </Typography>
              )}

              {values.attachments.length > 0 && (
                <Paper variant="outlined" sx={{ mt: 2, p: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Attached Files:
                  </Typography>
                  <List dense>
                    {values.attachments.map((file, index) => (
                      <ListItem
                        key={index}
                        secondaryAction={
                          <IconButton edge="end" onClick={() => removeFile(index)}>
                            <Delete />
                          </IconButton>
                        }
                      >
                        <ListItemIcon>
                          <InsertDriveFile />
                        </ListItemIcon>
                        <ListItemText
                          primary={file.name}
                          secondary={`${(file.size / 1024 / 1024).toFixed(2)} MB`}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              )}
            </Grid>

            {uploadProgress > 0 && (
              <Grid item xs={12}>
                <LinearProgress
                  variant="determinate"
                  value={uploadProgress}
                  sx={{ mb: 2 }}
                />
                <Typography variant="body2" color="text.secondary" align="center">
                  Uploading: {uploadProgress}%
                </Typography>
              </Grid>
            )}

            <Grid item xs={12}>
              <Button
                type="submit"
                variant="contained"
                fullWidth
                disabled={isSubmitting}
                sx={{ mt: 2 }}
              >
                {isSubmitting ? 'Creating Project...' : 'Create Project'}
              </Button>
            </Grid>
          </Grid>
        </Box>
      </Paper>
    </Container>
  );
};

// Profile Component
const Profile = () => {
  const { user } = useAuth();
  const [profileData, setProfileData] = useState(null);
  const [editMode, setEditMode] = useState(false);
  const [values, setValues] = useState({
    name: '',
    bio: '',
    skills: '',
    hourlyRate: ''
  });
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    loadProfile();
  }, []);

  const loadProfile = async () => {
    try {
      setIsLoading(true);
      const { data } = await api.get('/profile');
      setProfileData(data);
      setValues({
        name: data.profile.name || '',
        bio: data.profile.bio || '',
        skills: data.profile.skills?.join(', ') || '',
        hourlyRate: data.profile.hourlyRate || ''
      });
    } catch (error) {
      console.error('Failed to load profile:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const validateProfile = () => {
    const newErrors = {};
    
    if (!values.name.trim()) {
      newErrors.name = 'Name is required';
    }

    if (user.role === 'freelancer') {
      if (!values.skills.trim()) {
        newErrors.skills = 'Skills are required';
      }
      if (!values.hourlyRate || Number(values.hourlyRate) <= 0) {
        newErrors.hourlyRate = 'Valid hourly rate is required';
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const updateProfile = async (e) => {
    e.preventDefault();
    if (!validateProfile()) return;

    try {
      await api.put('/profile', {
        ...values,
        skills: values.skills.split(',').map(s => s.trim()).filter(Boolean),
        hourlyRate: user.role === 'freelancer' ? Number(values.hourlyRate) : undefined
      });
      
      setEditMode(false);
      loadProfile();
    } catch (error) {
      setErrors(prev => ({
        ...prev,
        submit: error.response?.data?.message || 'Failed to update profile'
      }));
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '70vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Container maxWidth="md">
      <Paper elevation={3} sx={{ p: 4, mt: 4 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h4">Profile</Typography>
          <Button 
            variant="outlined" 
            onClick={() => setEditMode(!editMode)}
          >
            {editMode ? 'Cancel' : 'Edit Profile'}
          </Button>
        </Box>

        {errors.submit && (
          <div className="mb-4 p-3 bg-red-100 text-red-700 rounded">
            {errors.submit}
          </div>
        )}

        {editMode ? (
          <Box component="form" onSubmit={updateProfile}>
            <Stack spacing={2}>
              <TextField
                label="Name"
                name="name"
                value={values.name}
                onChange={(e) => setValues({ ...values, name: e.target.value })}
                error={!!errors.name}
                helperText={errors.name}
                fullWidth
                required
              />
              <TextField
                label="Bio"
                name="bio"
                value={values.bio}
                onChange={(e) => setValues({ ...values, bio: e.target.value })}
                multiline
                rows={3}
                fullWidth
              />
              {user.role === 'freelancer' && (
                <>
                  <TextField
                    label="Skills (comma-separated)"
                    name="skills"
                    value={values.skills}
                    onChange={(e) => setValues({ ...values, skills: e.target.value })}
                    error={!!errors.skills}
                    helperText={errors.skills}
                    fullWidth
                    required
                  />
                  <TextField
                    label="Hourly Rate ($)"
                    name="hourlyRate"
                    type="number"
                    value={values.hourlyRate}
                    onChange={(e) => setValues({ ...values, hourlyRate: e.target.value })}
                    error={!!errors.hourlyRate}
                    helperText={errors.hourlyRate}
                    fullWidth
                    required
                    InputProps={{
                      startAdornment: <InputAdornment position="start">$</InputAdornment>
                    }}
                  />
                </>
              )}
              <Button variant="contained" type="submit">
                Save Changes
              </Button>
            </Stack>
          </Box>
        ) : (
          profileData && (
            <Box>
              <Typography variant="h5" gutterBottom>
                {profileData.profile.name}
              </Typography>
              <Typography variant="body1" gutterBottom>
                {profileData.profile.bio || 'No bio provided'}
              </Typography>
              {user.role === 'freelancer' && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle1">
                    Skills: {profileData.profile.skills?.join(', ') || 'None specified'}
                  </Typography>
                  <Typography variant="subtitle1">
                    Hourly Rate: ${profileData.profile.hourlyRate}/hr
                  </Typography>
                  <Typography variant="subtitle1">
                    Rating: {profileData.profile.rating || 'No ratings yet'}/5
                  </Typography>
                  <Typography variant="subtitle1">
                    Completed Projects: {profileData.profile.completedProjects || 0}
                  </Typography>
                </Box>
              )}
            </Box>
          )
        )}
      </Paper>
    </Container>
  );
};

const PaymentForm = ({ projectId, onSuccess }) => {
  const stripe = useStripe();
  const elements = useElements();
  const { user } = useAuth();
  const [error, setError] = useState(null);
  const [processing, setProcessing] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!stripe || !elements) return;

    setProcessing(true);
    setError(null);

    try {
      const { data } = await api.post('/payments/create-intent', { projectId });
      
      const { error: stripeError, paymentIntent } = await stripe.confirmCardPayment(
        data.clientSecret,
        {
          payment_method: {
            card: elements.getElement(CardElement),
            billing_details: { name: user.username },
          },
        }
      );

      if (stripeError) {
        throw new Error(stripeError.message);
      }

      await api.post('/payments/confirm', { 
        projectId, 
        paymentIntentId: paymentIntent.id 
      });

      onSuccess();
    } catch (error) {
      console.error('Payment error:', error);
      setError(error.message);
    } finally {
      setProcessing(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {error && (
         <div className="mb-4 p-3 bg-red-100 text-red-700 rounded">
          {error}
        </div>
      )}
      <Paper elevation={3} sx={{ p: 2, mb: 2 }}>
        <CardElement options={{
          style: {
            base: {
              fontSize: '16px',
              color: '#424770',
              '::placeholder': {
                color: '#aab7c4',
              },
            },
            invalid: {
              color: '#9e2146',
            },
          },
        }}/>
      </Paper>
      <Button 
        variant="contained" 
        fullWidth 
        type="submit"
        disabled={!stripe || processing}
      >
        {processing ? 'Processing...' : 'Pay Now'}
      </Button>
    </form>
  );
}

const ChatSystem = () => {
  const { user } = useAuth();
  const [chats, setChats] = useState([]);
  const [currentChat, setCurrentChat] = useState(null);
  const [message, setMessage] = useState('');
  const [socket, setSocket] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const messagesEndRef = useRef(null);
  const [pendingMessages, setPendingMessages] = useState([]);

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  // 1) Initialize Socket.io Connection
  useEffect(() => {
    let socketInstance = io(SOCKET_URL, {
      auth: { token: localStorage.getItem('token') },
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 2000,
      transports: ['websocket']
    });

    socketInstance.on('connect', () => {
      console.log('Socket connected with ID:', socketInstance.id);
      setIsConnected(true);
      setError(null);
      if (pendingMessages.length > 0 && currentChat) {
        pendingMessages.forEach((msg) => sendMessage(msg));
        setPendingMessages([]);
      }
    });

    socketInstance.on('disconnect', () => {
      console.log('Socket disconnected');
      setIsConnected(false);
    });

    socketInstance.on('error', (err) => {
      console.error('Socket error:', err);
      setError(`Connection error: ${err}`);
    });

    socketInstance.on('new_message', (data) => {
      handleNewMessage(data);
    });

    // Listen for system event: user joined
    socketInstance.on('user_joined', (data) => {
      console.log(`User joined chat: ${data.username}`);
      setChats(prevChats => {
        const updatedChats = [...prevChats];
        const idx = updatedChats.findIndex(c => c._id === data.chatId);
        if (idx !== -1) {
          const updatedChat = { ...updatedChats[idx] };
          updatedChat.messages = [
            ...updatedChat.messages,
            {
              _id: Date.now().toString(),
              sender: null,
              type: 'system',
              content: `${data.username} joined the chat`,
              timestamp: new Date()
            }
          ];
          updatedChats[idx] = updatedChat;
          if (currentChat && currentChat._id === data.chatId) {
            setCurrentChat(updatedChat);
          }
        }
        return updatedChats;
      });
    });

    setSocket(socketInstance);

    return () => {
      socketInstance.disconnect();
    };
  }, [pendingMessages, currentChat, user]);

  // 2) Load Chats
  useEffect(() => {
    const loadChats = async () => {
      try {
        setIsLoading(true);
        const { data } = await api.get('/chats');
        setChats(data);
      } catch (err) {
        console.error('Failed to load chats:', err);
        setError('Failed to load chats. Please try again.');
      } finally {
        setIsLoading(false);
      }
    };
    if (user) loadChats();
  }, [user]);

  // 3) Join selected chat room
  useEffect(() => {
    if (socket && currentChat) {
      socket.emit('join_chat', currentChat._id);
    }
  }, [socket, currentChat]);

  // 4) Scroll to bottom when messages update
  useEffect(() => {
    scrollToBottom();
  }, [currentChat?.messages, scrollToBottom]);

  const handleNewMessage = useCallback((data) => {
    setChats(prevChats => {
      const updatedChats = [...prevChats];
      const chatIndex = updatedChats.findIndex(c => c._id === data.chatId);
      if (chatIndex !== -1) {
        const chatToUpdate = { ...updatedChats[chatIndex] };
        chatToUpdate.messages = [...(chatToUpdate.messages || []), data.message];
        chatToUpdate.lastMessage = {
          content: data.message.content,
          timestamp: data.message.timestamp
        };
        updatedChats.splice(chatIndex, 1);
        updatedChats.unshift(chatToUpdate);
        if (currentChat && currentChat._id === data.chatId) {
          setCurrentChat(chatToUpdate);
        }
      }
      return updatedChats;
    });
    scrollToBottom();
  }, [currentChat, scrollToBottom]);

  const sendMessage = async (content) => {
    if (!content.trim() || !currentChat || !socket) return;
    const messageData = {
      chatId: currentChat._id,
      content: content.trim(),
      recipientId: currentChat.participants.find(p => p.user._id !== user._id)?.user._id
    };
    const optimisticMessage = {
      _id: Date.now().toString(),
      sender: user._id,
      content: content.trim(),
      timestamp: new Date(),
      status: 'sending'
    };
    setCurrentChat(prev => ({
      ...prev,
      messages: [...(prev.messages || []), optimisticMessage]
    }));
    if (!isConnected) {
      setPendingMessages(prev => [...prev, content]);
      setError('You are offline. Message will be sent when reconnected.');
      return;
    }
    try {
      socket.emit('send_message', messageData, (ack) => {
        if (ack?.error) {
          throw new Error(ack.error);
        }
        setMessage('');
      });
    } catch (err) {
      console.error('Failed to send message:', err);
      setCurrentChat(prev => ({
        ...prev,
        messages: prev.messages.filter(msg => msg._id !== optimisticMessage._id)
      }));
      setError('Failed to send message. Please try again.');
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage(message);
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '70vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Grid container spacing={2}>
      {/* LEFT: List of chats */}
      <Grid item xs={12} md={4}>
        <Paper elevation={3} sx={{ p: 2, height: '70vh', overflowY: 'auto' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            <Typography variant="h6">Chats</Typography>
            {!isConnected && <Chip size="small" color="error" label="Offline" />}
          </Box>
          {error && <div className="mb-4 p-3 bg-red-100 text-red-700 rounded">{error}</div>}
          <Stack spacing={1}>
            {chats.map((chat) => {
              const otherUserObj = chat.participants.find(p => p.user._id !== user._id);
              if (!otherUserObj) return null;
              const { username, isOnline } = otherUserObj.user;
              return (
                <Button
                  key={chat._id}
                  variant={currentChat?._id === chat._id ? 'contained' : 'outlined'}
                  onClick={() => setCurrentChat(chat)}
                  sx={{ justifyContent: 'flex-start', textAlign: 'left', p: 2 }}
                >
                  <Box sx={{ width: '100%' }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography>{username}</Typography>
                      {isOnline && <Chip size="small" color="success" label="Online" />}
                    </Box>
                    {chat.lastMessage && (
                      <Typography
                        variant="body2"
                        color="text.secondary"
                        sx={{
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap'
                        }}
                      >
                        {chat.lastMessage.content}
                      </Typography>
                    )}
                  </Box>
                </Button>
              );
            })}
          </Stack>
        </Paper>
      </Grid>
      {/* RIGHT: Chat messages + input */}
      <Grid item xs={12} md={8}>
        {currentChat ? (
          <Paper elevation={3} sx={{ p: 2, height: '70vh', display: 'flex', flexDirection: 'column' }}>
            <Box sx={{ mb: 2 }}>
              <Typography variant="h6">
                {currentChat.participants.find(p => p.user._id !== user._id)?.user.username}
              </Typography>
            </Box>
            <Box sx={{ flexGrow: 1, overflowY: 'auto', mb: 2, p: 1 }}>
              {currentChat.messages.map((msg, i) => {
                if (msg.type === 'system') {
                  return (
                    <Box key={i} sx={{ display: 'flex', justifyContent: 'center', mb: 1 }}>
                      <Typography variant="caption" sx={{ fontStyle: 'italic', color: 'gray' }}>
                        {msg.content}
                      </Typography>
                    </Box>
                  );
                } else {
                  const isOwnMessage = msg.sender === user._id;
                  return (
                    <Box key={i} sx={{ display: 'flex', justifyContent: isOwnMessage ? 'flex-end' : 'flex-start', mb: 1 }}>
                      <Paper elevation={1} sx={{
                        p: 2,
                        bgcolor: isOwnMessage ? 'primary.main' : 'grey.200',
                        color: isOwnMessage ? 'white' : 'text.primary',
                        maxWidth: '70%'
                      }}>
                        <Typography variant="body1">{msg.content}</Typography>
                        <Typography variant="caption" sx={{
                          display: 'block',
                          mt: 0.5,
                          color: isOwnMessage ? 'rgba(255,255,255,0.7)' : 'text.secondary'
                        }}>
                          {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          {msg.status === 'sending' && ' • Sending...'}
                        </Typography>
                      </Paper>
                    </Box>
                  );
                }
              })}
              <div ref={messagesEndRef} />
            </Box>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <TextField
                placeholder="Type a message..."
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                onKeyPress={handleKeyPress}
                fullWidth
                multiline
                maxRows={4}
                disabled={!isConnected}
                InputProps={{ sx: { borderRadius: 2 } }}
              />
              <Button
                variant="contained"
                onClick={() => sendMessage(message)}
                disabled={!message.trim() || !isConnected}
                sx={{ borderRadius: 2 }}
              >
                Send
              </Button>
            </Box>
          </Paper>
        ) : (
          <Paper elevation={3} sx={{
            p: 2,
            height: '70vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Typography color="text.secondary">
              Select a chat to start messaging
            </Typography>
          </Paper>
        )}
      </Grid>
    </Grid>
  );
};

const Layout = ({ children }) => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const navLinks = [
    { icon: <HomeIcon sx={{ color: 'inherit' }} />, label: 'Home', path: '/' },
    { icon: <WorkIcon sx={{ color: 'inherit' }} />, label: 'Projects', path: '/projects' },
    { icon: <ChatIcon sx={{ color: 'inherit' }} />, label: 'Messages', path: '/chat' },
    { icon: <PersonIcon sx={{ color: 'inherit' }} />, label: 'Profile', path: '/profile' }
  ];

  return (
    <div className="flex h-screen bg-gray-50 dark:bg-gray-900 text-gray-800 dark:text-gray-200">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 text-gray-800 dark:text-white p-4 shadow-md fixed top-0 left-0 right-0 z-50 flex justify-between items-center h-16">
        <div className="text-xl font-semibold">Freelance Platform</div>
        <div className="text-sm">Welcome, {user?.username}</div>
      </header>

      {/* Sidebar */}
      <aside className="w-60 bg-gray-100 dark:bg-gray-850 p-4 border-r border-gray-200 dark:border-gray-700 fixed pt-16 h-full flex flex-col justify-between">
        <nav className="mt-4">
          <ul>
            {navLinks.map((link) => (
              <li key={link.path} className="mb-2">
                <button
                  onClick={() => navigate(link.path)}
                  className="flex items-center space-x-3 p-2 rounded-md hover:bg-gray-200 dark:hover:bg-gray-700 w-full text-left text-gray-700 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-primary"
                >
                  <span className="w-6 h-6 flex items-center justify-center">{link.icon}</span>
                  <span>{link.label}</span>
                </button>
              </li>
            ))}
          </ul>
        </nav>
        <div className="mt-auto mb-4"> {/* Pushes logout to the bottom */}
          <Button
            variant="ghost"
            onClick={logout}
            className="w-full justify-start text-red-600 hover:bg-red-100 hover:text-red-700 dark:text-red-400 dark:hover:bg-red-800 dark:hover:text-red-300 focus:outline-none focus:ring-2 focus:ring-red-500"
          >
            <LogOut className="mr-3 h-5 w-5" />
            Logout
          </Button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-grow p-6 pt-20 ml-60"> 
        {/* pt-20 to offset header (h-16 -> 4rem = 64px, so 5rem = 80px), ml-60 to offset sidebar (w-60 -> 15rem = 240px) */}
        {children}
      </main>
    </div>
  );
};

const App = () => {
  // Theme object and ThemeProvider, CssBaseline, GlobalStyles are removed.

  return (
    // <ThemeProvider theme={theme}> // Removed
    //   <CssBaseline /> // Removed
    //   <GlobalStyles styles={{ body: { backgroundColor: '#f7f9fc' } }} /> // Removed
      <ErrorBoundary>
        <BrowserRouter>
          <AuthProvider>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/register" element={<RegisterPage />} />
              <Route path="/" element={
                <ProtectedRoute>
                  <Layout><ProjectsList /></Layout>
                </ProtectedRoute>
              } />
              <Route path="/projects" element={
                <ProtectedRoute>
                  <Layout><ProjectsList /></Layout>
                </ProtectedRoute>
              } />
              <Route path="/projects/:id" element={
                <ProtectedRoute>
                  <Layout><ProjectDetails /></Layout>
                </ProtectedRoute>
              } />
              <Route path="/create-project" element={
                <ProtectedRoute>
                  <Layout><CreateProject /></Layout>
                </ProtectedRoute>
              } />
              <Route path="/chat" element={
                <ProtectedRoute>
                  <Layout><ChatSystem /></Layout>
                </ProtectedRoute>
              } />
              <Route path="/profile" element={
                <ProtectedRoute>
                  <Layout><Profile /></Layout>
                </ProtectedRoute>
              } />
            </Routes>
          </AuthProvider>
        </BrowserRouter>
      </ErrorBoundary>
    // </ThemeProvider> // Removed
  );
};

export default App;
