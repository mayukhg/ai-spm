# AI Security Posture Management (AI-SPM) Frontend Documentation

## Overview

The AI-SPM frontend is a modern, responsive React application built with TypeScript that provides a comprehensive interface for managing AI security posture. It serves as the primary user interface for security professionals to monitor, assess, and manage AI/ML assets, vulnerabilities, compliance, and threats in real-time.

## Technology Stack

### Core Technologies
- **React 18**: Modern React framework with hooks and function components
- **TypeScript**: Full type safety across the application
- **Vite**: Fast build tool and development server
- **Wouter**: Lightweight routing library for client-side navigation

### UI and Styling
- **shadcn/ui**: Component library built on Radix UI primitives
- **Radix UI**: Accessible, unstyled UI components
- **Tailwind CSS**: Utility-first CSS framework
- **Lucide React**: Icon library for consistent iconography
- **CSS Variables**: Dynamic theming system supporting light/dark modes

### State Management and Data Fetching
- **TanStack Query (React Query v5)**: Server state management with caching
- **React Context**: Local state management for authentication and user context
- **React Hook Form**: Form state management with validation
- **Zod**: Schema validation for forms and API responses

## Project Structure

```
client/src/
├── components/           # Reusable UI components
│   ├── charts/          # Data visualization components
│   ├── dashboard/       # Dashboard-specific components
│   ├── layout/          # Layout components (Header, Sidebar)
│   └── ui/              # shadcn/ui component library
├── hooks/               # Custom React hooks
├── lib/                 # Utility libraries and configurations
├── pages/               # Page components for routing
├── types/               # TypeScript type definitions
├── App.tsx              # Main application component
├── main.tsx             # Application entry point
└── index.css            # Global styles and CSS variables
```

## Architecture Patterns

### Component-Based Architecture
The application follows a modular component-based architecture with clear separation of concerns:

- **Page Components**: Top-level route components that orchestrate layout and data
- **Layout Components**: Reusable layout elements (Header, Sidebar)
- **Feature Components**: Business logic components for specific features
- **UI Components**: Presentational components from shadcn/ui library

### State Management Strategy
- **Server State**: Managed by TanStack Query with automatic caching and invalidation
- **Authentication State**: Managed by React Context with persistent session handling
- **Form State**: Managed by React Hook Form with Zod validation
- **UI State**: Local component state using React hooks

### Routing and Navigation
- **Client-Side Routing**: Wouter for lightweight routing without React Router overhead
- **Protected Routes**: Authentication wrapper for secured pages
- **Role-Based Access**: Navigation items filtered by user role permissions

## Key Features and Components

### Authentication System (`hooks/use-auth.tsx`)
- **Session-Based Authentication**: Secure session management with HTTP-only cookies
- **Role-Based Access Control**: Support for CISO, analyst, engineer, and compliance officer roles
- **Automatic Token Refresh**: Seamless session management with error handling
- **Login/Logout/Register**: Complete authentication flow with validation

```typescript
const { user, loginMutation, logoutMutation, isLoading } = useAuth();
```

### Dashboard (`pages/dashboard.tsx`)
The main dashboard provides a comprehensive overview of the security posture:
- **Real-Time Metrics**: Live updates of key security indicators
- **Interactive Charts**: Security trend visualization with Recharts
- **Asset Management**: Quick access to AI asset inventory
- **Alert Feed**: Real-time security alerts and notifications
- **Compliance Status**: Framework compliance overview
- **Quick Actions**: Immediate access to common tasks

### Navigation System (`components/layout/sidebar.tsx`)
- **Collapsible Sidebar**: Space-efficient navigation with expand/collapse
- **Role-Based Menu**: Dynamic menu items based on user permissions
- **Active State Management**: Visual indication of current page
- **User Profile Integration**: Integrated user information and logout

### Data Visualization (`components/charts/`)
- **Security Trend Charts**: Time-series data visualization
- **Compliance Metrics**: Progress indicators and status charts
- **Vulnerability Distribution**: Risk-level categorization charts
- **Real-Time Updates**: Live data refresh with polling

### Form Management
- **Type-Safe Forms**: Zod schema validation with TypeScript integration
- **Real-Time Validation**: Client-side validation with error feedback
- **Server Integration**: Seamless API integration with TanStack Query mutations

## Pages and Routes

### Public Routes
- `/auth` - Authentication page (login/register)

### Protected Routes (Authentication Required)
- `/` - Main dashboard with security overview
- `/ai-assets` - AI/ML asset inventory and management
- `/vulnerabilities` - Vulnerability tracking and remediation
- `/monitoring` - Real-time system monitoring and alerts
- `/compliance` - Compliance framework management and assessments

### Route Protection
```typescript
<ProtectedRoute path="/dashboard" component={Dashboard} />
```

## Styling and Theming

### Design System
- **CSS Variables**: Consistent color system across light/dark themes
- **Component Variants**: Standardized component styling patterns
- **Responsive Design**: Mobile-first responsive layouts
- **Accessibility**: WCAG-compliant color contrast and keyboard navigation

### Color Palette
```css
/* Light Theme */
--primary: 221 83% 53%;      /* #1565C0 - Primary blue */
--secondary: 210 40% 96%;    /* #F1F5F9 - Light gray */
--destructive: 0 84% 60%;    /* #EF4444 - Error red */
--success: 142 76% 36%;      /* #16A34A - Success green */
--warning: 25 95% 53%;       /* #F59E0B - Warning amber */
```

### Theme System
- **Dark Mode Support**: Complete dark theme implementation
- **CSS Custom Properties**: Dynamic theme switching
- **Tailwind Integration**: Utility-first styling with theme variables

## Data Flow and API Integration

### Query Client Configuration
```typescript
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn({ on401: "throw" }),
      refetchInterval: false,
      refetchOnWindowFocus: false,
      staleTime: Infinity,
      retry: false,
    },
  },
});
```

### API Request Patterns
- **Automatic Error Handling**: Centralized error management with toast notifications
- **Authentication Integration**: Automatic credential inclusion in requests
- **Response Type Safety**: Full TypeScript integration with shared schemas

### Real-Time Features
- **Polling Updates**: Automatic data refresh for critical information
- **Alert Notifications**: Real-time security alert display
- **Live Status Indicators**: System health and connectivity status

## User Experience Features

### Loading States
- **Skeleton Loading**: Progressive loading indicators for better perceived performance
- **Suspense Boundaries**: Error boundaries for graceful error handling
- **Optimistic Updates**: Immediate UI feedback for user actions

### Accessibility
- **Keyboard Navigation**: Full keyboard accessibility support
- **Screen Reader Support**: Semantic HTML and ARIA attributes
- **Color Blind Friendly**: High contrast color choices
- **Focus Management**: Proper focus handling for modal dialogs

### Responsive Design
- **Mobile-First**: Optimized for mobile devices with progressive enhancement
- **Flexible Layouts**: CSS Grid and Flexbox for adaptive layouts
- **Touch-Friendly**: Appropriate touch targets and gestures

## Performance Optimizations

### Bundle Optimization
- **Code Splitting**: Automatic route-based code splitting
- **Tree Shaking**: Elimination of unused code
- **Asset Optimization**: Optimized image and asset loading

### Caching Strategy
- **Query Caching**: Intelligent server state caching with TanStack Query
- **Static Asset Caching**: Browser caching for static resources
- **Background Updates**: Stale-while-revalidate patterns

### Memory Management
- **Component Cleanup**: Automatic cleanup of subscriptions and timers
- **Query Invalidation**: Proper cache invalidation strategies
- **Event Listener Management**: Cleanup of global event listeners

## Security Considerations

### Client-Side Security
- **XSS Prevention**: Secure rendering and sanitization
- **CSRF Protection**: Proper CSRF token handling
- **Secure Storage**: No sensitive data in localStorage
- **Input Validation**: Client-side validation with server-side verification

### Authentication Security
- **Session-Based Auth**: Secure HTTP-only cookie sessions
- **Automatic Logout**: Session timeout and automatic cleanup
- **Role Validation**: Client-side role checking with server-side enforcement

## Development Workflow

### Development Server
```bash
npm run dev  # Starts Vite development server with hot reload
```

### Type Safety
- **Shared Schemas**: TypeScript types shared between frontend and backend
- **Compile-Time Checking**: Full type checking during development
- **API Contract Validation**: Runtime validation with Zod schemas

### Component Development
- **Component Library**: Standardized component patterns with shadcn/ui
- **Storybook Integration**: Component documentation and testing
- **Design System**: Consistent design patterns and component APIs

## Browser Compatibility

### Supported Browsers
- **Modern Browsers**: Chrome 88+, Firefox 85+, Safari 14+, Edge 88+
- **Mobile Browsers**: iOS Safari 14+, Chrome Mobile 88+
- **Feature Detection**: Graceful degradation for unsupported features

### Polyfills and Fallbacks
- **ES2020+ Features**: Modern JavaScript features with appropriate polyfills
- **CSS Grid/Flexbox**: Modern layout with fallbacks
- **Intersection Observer**: Performance optimization with polyfill support

## Future Enhancements

### Planned Features
- **Progressive Web App**: Service worker integration for offline functionality
- **WebSocket Integration**: Real-time data streaming for live updates
- **Advanced Filtering**: Enhanced search and filtering capabilities
- **Bulk Operations**: Multi-select and bulk action support
- **Custom Dashboards**: User-configurable dashboard layouts

### Technical Improvements
- **Micro-Frontend Architecture**: Potential migration to micro-frontend pattern
- **GraphQL Integration**: Enhanced data fetching with GraphQL
- **Advanced Caching**: Redis integration for improved performance
- **Internationalization**: Multi-language support with i18n