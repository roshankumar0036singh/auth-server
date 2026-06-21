import { AxiosInstance, InternalAxiosRequestConfig } from 'axios';
import { AuthClient } from './AuthClient';

// 1. Fix: Augment Axios types so TypeScript recognizes our custom '_retry' flag
declare module 'axios' {
  export interface InternalAxiosRequestConfig {
    _retry?: boolean;
  }
}

interface FailedRequestQueueItem {
  resolve: (token: string) => void;
  reject: (error: any) => void;
}

// 3. Fix: Added explicit return type declaration ': () => void' for cleanup
export function createAuthInterceptor(axiosInstance: AxiosInstance, authClient: AuthClient): () => void {
  let isRefreshing = false;
  let failedQueue: FailedRequestQueueItem[] = [];

  const processQueue = (error: any, token: string | null = null) => {
    failedQueue.forEach((promise) => {
      if (error) {
        promise.reject(error);
      } else if (token != null) { // 2. Fix: Ensure checking strict null/undefined
        promise.resolve(token);
      } else {
        // 2. Fix: Prevent promises from hanging if refresh returns empty
        promise.reject(new Error('Token refresh succeeded but no access token returned'));
      }
    });
    failedQueue = [];
  };

  // 3. Fix: Capture the unique Interceptor ID
  const requestInterceptorId = axiosInstance.interceptors.request.use(
    (config) => {
      const token = authClient.getAccessToken(); 
      if (token && config.headers) {
        config.headers['Authorization'] = `Bearer ${token}`;
      }
      return config;
    },
    (error) => Promise.reject(error)
  );

  // 3. Fix: Capture the unique Interceptor ID
  const responseInterceptorId = axiosInstance.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config as InternalAxiosRequestConfig;

      if (error.response?.status === 401 && originalRequest && !originalRequest._retry) {
        
        if (isRefreshing) {
          return new Promise((resolve, reject) => {
            failedQueue.push({
              resolve: (token: string) => {
                if (originalRequest.headers) {
                  originalRequest.headers['Authorization'] = `Bearer ${token}`;
                }
                resolve(axiosInstance(originalRequest));
              },
              reject: (err: any) => reject(err),
            });
          });
        }

        originalRequest._retry = true;
        isRefreshing = true;

        try {
          const session = await authClient.refresh(); 
          const newAccessToken = session.accessToken;

          // 2. Fix: Defensive guard clause for the returned token
          if (!newAccessToken) {
            throw new Error('Token refresh succeeded but no access token returned');
          }

          processQueue(null, newAccessToken);

          if (originalRequest.headers) {
            originalRequest.headers['Authorization'] = `Bearer ${newAccessToken}`;
          }
          return axiosInstance(originalRequest);
        } catch (refreshError) {
          processQueue(refreshError, null);
          await authClient.logout();
          return Promise.reject(refreshError);
        } finally {
          isRefreshing = false;
        }
      }

      return Promise.reject(error);
    }
  );

  // 3. Fix: Return an executable eject/cleanup function for SPAs and testing
  return () => {
    axiosInstance.interceptors.request.eject(requestInterceptorId);
    axiosInstance.interceptors.response.eject(responseInterceptorId);
  };
}