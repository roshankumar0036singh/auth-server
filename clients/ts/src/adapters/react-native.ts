import { StorageAdapter } from '../types';

/**
 * Storage adapter for React Native using AsyncStorage.
 * 
 * Usage:
 * import AsyncStorage from '@react-native-async-storage/async-storage';
 * import { createReactNativeAdapter } from '@authserver/client/react-native';
 * 
 * const authClient = new AuthClient({
 *   serverUrl: '...',
 *   clientId: '...',
 *   storageAdapter: createReactNativeAdapter(AsyncStorage)
 * });
 */
export const createReactNativeAdapter = (asyncStorageInstance: any): StorageAdapter => {
  return {
    getItem: async (key: string) => {
      return await asyncStorageInstance.getItem(key);
    },
    setItem: async (key: string, value: string) => {
      await asyncStorageInstance.setItem(key, value);
    },
    removeItem: async (key: string) => {
      await asyncStorageInstance.removeItem(key);
    }
  };
};
