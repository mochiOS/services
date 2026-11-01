// Host harness for the actual clangDriver/clangBasic libraries. Source jobs are
// inspected with -###; this does not substitute a different compiler frontend.
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Basic/MacroBuilder.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/TargetOptions.h"
#include "clang/Driver/Compilation.h"
#include "clang/Driver/Driver.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include <memory>

class Diagnostics final : public clang::DiagnosticConsumer {
public:
  void HandleDiagnostic(clang::DiagnosticsEngine::Level Level,
                        const clang::Diagnostic &Info) override {
    DiagnosticConsumer::HandleDiagnostic(Level, Info);
    llvm::SmallString<256> Message;
    Info.FormatDiagnostic(Message);
    llvm::errs() << Message << '\n';
  }
};

int main(int argc, const char **argv) {
  llvm::InitLLVM Init(argc, argv);
  llvm::IntrusiveRefCntPtr<clang::DiagnosticIDs> IDs(new clang::DiagnosticIDs);
  llvm::IntrusiveRefCntPtr<clang::DiagnosticOptions> Options(
      new clang::DiagnosticOptions);
  clang::DiagnosticsEngine Diags(IDs, Options, new Diagnostics);
  if (argc >= 3 && llvm::StringRef(argv[1]) == "--target-defines") {
    auto TargetOptions = std::make_shared<clang::TargetOptions>();
    TargetOptions->Triple = argv[2];
    std::unique_ptr<clang::TargetInfo> Target(
        clang::TargetInfo::CreateTargetInfo(Diags, TargetOptions));
    if (!Target)
      return 1;
    clang::LangOptions Language;
    Language.GNUMode = true;
    Language.POSIXThreads = argc == 4;
    clang::MacroBuilder Builder(llvm::outs());
    Target->getTargetDefines(Language, Builder);
    llvm::outs() << "pointer-width="
                 << Target->getPointerWidth(clang::LangAS::Default)
                 << " long-width=" << Target->getLongWidth() << '\n';
    return 0;
  }
  clang::driver::Driver Driver(argv[0], "x86_64-unknown-mochios", Diags);
  std::unique_ptr<clang::driver::Compilation> Compilation(
      Driver.BuildCompilation(llvm::ArrayRef(argv, argc)));
  if (!Compilation || Diags.hasErrorOccurred())
    return 1;
  llvm::SmallVector<std::pair<int, const clang::driver::Command *>, 4> Failures;
  int Result = Driver.ExecuteCompilation(*Compilation, Failures);
  if (Result == 0 && !Failures.empty())
    Result = Failures.front().first;
  return Result < 0 ? 1 : Result;
}
