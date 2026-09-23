# shopkeep 的常用入口。Makefile 比 npm scripts 多一层用途：
# 在没装 node_modules 的机器上也能 make vectors 提示依赖缺失，
# 而不是抛一屏 module not found。

NODE ?= node

.PHONY: test typecheck vectors capture clean

test:
	npx vitest run

typecheck:
	npx tsc --noEmit

vectors:
	npx tsx src/cli.ts vectors

# 校验一份抓取的 proof 响应：make capture FILE=proofs.json
capture:
	@test -n "$(FILE)" || (echo "用法: make capture FILE=proofs.json" && exit 2)
	npx tsx src/cli.ts capture $(FILE)

clean:
	rm -rf node_modules dist
