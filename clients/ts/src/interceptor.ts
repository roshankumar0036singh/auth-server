import { AxiosInstance, InternalAxiosRequestConfig } from 'axios';
import { AuthClient } from './AuthClient';

declare module 'axios' {
  export interface InternalAxiosRequestConfig {
    _retry?: boolean;
  }
}

interface FailedRequestQueueItem {
  resolve: (token: string) => void;
  reject: (error: any) => void;
}

export function createAuthInterceptor(axiosInstance: AxiosInstance, authClient: AuthClient): () => void {
  let isRefreshing = false;
  let failedQueue: FailedRequestQueueItem[] = [];

  const processQueue = (error: any, token: string | null = null) => {
    failedQueue.forEach((promise) => {
      if (error) {
        promise.reject(error);
      } else if (typeof token === 'string' && token.length > 0) { // Fix L25: Avoids unexpected negated condition
        promise.resolve(token);
      } else {
        promise.reject(new Error('Token refresh succeeded but no access token returned'));
      }
    });
    failedQueue = [];
  };

  const requestInterceptorId = axiosInstance.interceptors.request.use(
    (config) => {
      const token = authClient.getAccessToken(); 
      if (token && config.headers) {
        config.headers['Authorization'] = `Bearer ${token}`;
      }
      return config;
    },
    (error) => Promise.reject(error) // Left as-is: This isn't an async function, so Promise.reject is correct here
  );

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
          throw refreshError; // Fix L90: Prefer 'throw error' over 'return Promise.reject' inside async blocks
        } finally {
          isRefreshing = false;
        }
      }

      throw error; // Fix L96: Prefer 'throw error' over 'return Promise.reject' inside async blocks
    }
  );

  return () => {
    axiosInstance.interceptors.request.eject(requestInterceptorId);
    axiosInstance.interceptors.response.eject(responseInterceptorId);
  };
}