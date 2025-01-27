PROJECT_NAME="xmtpv3"

RED='\033[0;31m'
NC='\033[0m' # No Color

WORKSPACE_MANIFEST="$(cargo locate-project --workspace --message-format=plain)"
WORKSPACE_PATH="$(dirname $WORKSPACE_MANIFEST)"
BINDINGS_MANIFEST="$WORKSPACE_PATH/bindings_ffi/Cargo.toml"
BINDINGS_PATH="$(dirname $BINDINGS_MANIFEST)"
TARGET_DIR="$WORKSPACE_PATH/target"
XMTP_ANDROID="${1:-$(realpath ../../xmtp-android)}"

if [ ! -d $XMTP_ANDROID ]; then
  echo "${RED}xmtp-android directory not detected${NC}"
  echo "${RED}Ensure \`github.com/xmtp/xmtp_android\` is cloned as a sibling directory or passed as the first argument to this script.${NC}"
  exit
fi
echo "Android Directory: $XMTP_ANDROID"

cd $WORKSPACE_PATH
cargo build --release -p xmtpv3
rm -f $BINDINGS_PATH/src/uniffi/$PROJECT_NAME/$PROJECT_NAME.kt
cargo run --bin ffi-uniffi-bindgen \
  --manifest-path $BINDINGS_MANIFEST \
  --features uniffi/cli --release -- \
  generate \
  --lib-file $TARGET_DIR/release/lib$PROJECT_NAME.dylib $BINDINGS_PATH/src/$PROJECT_NAME.udl \
  --language kotlin

cd $BINDINGS_PATH
make libxmtp-version
cp libxmtp-version.txt src/uniffi/$PROJECT_NAME/

cp $BINDINGS_PATH/src/uniffi/xmtpv3/xmtpv3.kt $XMTP_ANDROID/library/src/main/java/xmtpv3.kt
cp $BINDINGS_PATH/src/uniffi/xmtpv3/libxmtp-version.txt $XMTP_ANDROID/library/src/main/java/libxmtp-version.txt
