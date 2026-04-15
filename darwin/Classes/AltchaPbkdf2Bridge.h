#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// C++ PBKDF2 solver shared by iOS and macOS.
///
/// The method is synchronous and blocking — call it from a background thread.
/// Returns the found counter, or -1 on timeout / not found.
/// When the return value is >= 0, @p outKey contains the derived key bytes.
@interface AltchaPbkdf2Bridge : NSObject

/// @param hashId  256 (PBKDF2-SHA-256), 384 (PBKDF2-SHA-384), or 512 (PBKDF2-SHA-512)
/// @param prefix  Binary keyPrefix (even-length hex decoded); pass nil to do a hex comparison
///                (slower, uncommon). When non-nil its length must be <= keyLength.
+ (int)solveWithNonce:(NSData *)nonce
                 salt:(NSData *)salt
                 cost:(int)cost
            keyLength:(int)keyLength
               hashId:(int)hashId
               prefix:(nullable NSData *)prefix
          workerCount:(int)workerCount
            timeoutMs:(long long)timeoutMs
               outKey:(NSMutableData *)outKey;

@end

NS_ASSUME_NONNULL_END
