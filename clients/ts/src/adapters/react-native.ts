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
export interface AsyncStorageLike {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

export const createReactNativeAdapter = (asyncStorageInstance: AsyncStorageLike): StorageAdapter => {
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
