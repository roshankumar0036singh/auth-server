import { AxiosInstance } from 'axios';
import { AuthClient } from './AuthClient';

interface FailedRequestQueueItem {
  resolve: (token: string) => void;
  reject: (error: any) => void;
}

export function createAuthInterceptor(axiosInstance: AxiosInstance, authClient: AuthClient) {
  let isRefreshing = false;
  let failedQueue: FailedRequestQueueItem[] = [];

  const processQueue = (error: any, token: string | null = null) => {
    failedQueue.forEach((promise) => {
      if (error) {
        promise.reject(error);
      } else if (token) {
        promise.resolve(token);
      }
    });
    failedQueue = [];
  };

  // 1. Request Interceptor: Attach the current token to outgoing requests
  axiosInstance.interceptors.request.use(
    (config) => {
      const token = authClient.getAccessToken(); 
      if (token && config.headers) {
        config.headers['Authorization'] = `Bearer ${token}`;
      }
      return config;
    },
    (error) => Promise.reject(error)
  );

  // 2. Response Interceptor: Catch 401 errors and handle seamless token refreshes
  axiosInstance.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config;

      if (error.response?.status === 401 && !originalRequest._retry) {
        
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
          // Hits your AuthClient's deduplicated refresh route
          const session = await authClient.refresh(); 
          const newAccessToken = session.accessToken;

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
}