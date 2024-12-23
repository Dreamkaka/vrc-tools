import { Context, filterKeys, Schema, segment } from 'koishi'
import axios from 'axios'

export const name = 'vrchat-api'

export interface Config {
  userAgent: string
}

export const Config: Schema<Config> = Schema.object({
  userAgent: Schema.string().default('KoishiBot/1.0.0').description('User-Agent')
})

const BASE_URL = 'https://api.vrchat.cloud/api/1'

// 在文件开头添加类型定义
interface VRChatAuth {
  userId: string
  currentUser: any
  authCookie: string
  authToken: string
  timestamp: number
}

// 添加数据库表类型声明
declare module 'koishi' {
  interface Tables {
    vrchat_auth: VRChatAuth
  }
}

export function apply(ctx: Context) {
  // 初始化数据库表
  ctx.model.extend('vrchat_auth', {
    // 用户ID作为主键
    userId: 'string',
    // 存储用户信息（JSON字符串）
    currentUser: 'json',
    // 存储认证Cookie
    authCookie: 'string',
    // 存储认证Token
    authToken: 'string',
    // 存储最后更新时间
    timestamp: 'integer',
  }, {
    primary: 'userId',
  })

  // 修改保存凭据的函数
  async function saveAuth(userId: string, data: Partial<VRChatAuth>) {
    try {
      if (!userId) {
        ctx.logger('vrchat-api').warn('保存凭据失败: 缺少用户ID')
        return
      }

      const authData = {
        userId,
        currentUser: data.currentUser || {},
        authCookie: data.authCookie || '',
        authToken: data.authToken || '',
        timestamp: Date.now(),
      }

      // 先尝试删除旧数据
      await ctx.model.remove('vrchat_auth', { userId })
      // 然后插入新数据
      await ctx.model.create('vrchat_auth', authData)

      ctx.logger('vrchat-api').info(`已保存用户 ${userId} 的凭据`)
    } catch (error) {
      ctx.logger('vrchat-api').error('保存凭据失败:', error)
      throw error // 向上传递错误以便调用者处理
    }
  }

  // 添加读取凭据的函数
  async function loadAuth(userId: string): Promise<VRChatAuth | null> {
    try {
      const [auth] = await ctx.model.get('vrchat_auth', { userId })
      if (!auth) return null

      // 检查凭据是否过期（这里设置7天过期）
      const expired = Date.now() - auth.timestamp > 7 * 24 * 60 * 60 * 1000
      if (expired) {
        await ctx.model.remove('vrchat_auth', { userId })
        return null
      }

      return auth as VRChatAuth
    } catch (error) {
      ctx.logger('vrchat-api').error('读取凭据失败:', error)
      return null
    }
  }

  // 存储会话信息
  let currentUser = null
  let authCookie = null
  let authToken = null

  // 登录命令
  ctx.command('vrchat.login', '登录到VRChat账号')
    .action(async ({ session }) => {
      // 尝试加载已有凭据
      if (session.userId) {
        const savedAuth = await loadAuth(session.userId)
        if (savedAuth && savedAuth.currentUser) {
          currentUser = savedAuth.currentUser
          authCookie = savedAuth.authCookie
          authToken = savedAuth.authToken
          return `已恢复登录状态！欢迎回来 ${currentUser?.displayName || '用户'}`
        }
      }

      // 请求输入账号
      await session.send('请输入VRChat账号:')
      const username = await session.prompt()
      if (!username) return '登录已取消'

      // 请求输入密码
      await session.send('请输入VRChat密码:')
      const password = await session.prompt()
      if (!password) return '登录已取消'

      try {
        // 创建headers
        const headers = {
          'User-Agent': ctx.config.userAgent,
          'Cookie': 'apiKey=JlE5Jldo5Jibnk5O5hTx6XVqsJu4WJ26'
        }

        // 添加Basic认证
        const auth = Buffer.from(`${username}:${password}`).toString('base64')
        headers['Authorization'] = `Basic ${auth}`

        // 获取当前用户信息
        const response = await axios.get(`${BASE_URL}/auth/user`, {
          headers,
          withCredentials: true
        })

        currentUser = response.data
        authToken = headers['Authorization']

        // 检查是否需要2FA
        if (currentUser.requiresTwoFactorAuth) {
          if (currentUser.requiresTwoFactorAuth[0] === 'emailOtp') {
            await session.send('需要邮箱验证码，请使用 vrchat.verify <验证码> 命令输入验证码')
            return '请查看邮箱并输入验证码'
          } else if (currentUser.requiresTwoFactorAuth[0] === 'totp') {
            await session.send('需要2FA验证码，请使用 vrchat.verify <验证码> 命令输入验证码')
            return '请输入2FA验证码'
          }
        }

        // 保存认证Cookie
        if (response.headers['set-cookie']) {
          authCookie = response.headers['set-cookie'][0]
        }

        // 登录成功后保存凭据
        if (session.userId && currentUser) {
          try {
            await saveAuth(session.userId, {
              currentUser,
              authCookie,
              authToken,
            })
          } catch (error) {
            ctx.logger('vrchat-api').error('保存凭据时出错:', error)
            // 继续执行，不影响登录成功的返回
          }
        }

        return `登录成功！欢迎 ${currentUser?.displayName || '用户'}`
      } catch (error) {
        ctx.logger('vrchat-api').error('登录失败:', error)
        return '登录失败，请检查账号密码或网络连接'
      }
    })

  // 添加登出命令
  ctx.command('vrchat.logout', '登出VRChat账号')

    .action(async ({ session }) => {
      if (!currentUser) {
        return '当前未登录'
      }

      try {
        if (session.userId) {
          await ctx.model.remove('vrchat_auth', { userId: session.userId })
        }

        currentUser = null
        authCookie = null
        authToken = null

        return '已成功登出'
      } catch (error) {
        ctx.logger('vrchat-api').error('登出失败:', error)
        return '登出失败，请稍后重试'
      }
    })

  // 验证码命令
  ctx.command('vrchat.verify <code>', '输入VRChat验证码')
    .action(async ({ session }, code) => {
      if (!currentUser?.requiresTwoFactorAuth) {
        return '当前不需要输入验证码'
      }

      try {
        const headers = {
          'User-Agent': ctx.config.userAgent,
          'Content-Type': 'application/json',
          'Cookie': `apiKey=JlE5Jldo5Jibnk5O5hTx6XVqsJu4WJ26${authCookie ? `; ${authCookie}` : ''}`,
          'Authorization': authToken
        }

        const endpoint = currentUser.requiresTwoFactorAuth[0] === 'emailOtp'
          ? '/auth/twofactorauth/emailotp/verify'
          : '/auth/twofactorauth/totp/verify'

        // 发送验证码
        const verifyResponse = await axios.post(`${BASE_URL}${endpoint}`,
          { code },
          { headers }
        )

        // 保存新的Cookie
        if (verifyResponse.headers['set-cookie']) {
          authCookie = verifyResponse.headers['set-cookie'][0]
        }

        // 验证成功后重新获取用户信息
        const response = await axios.get(`${BASE_URL}/auth/user`, {
          headers: {
            ...headers,
            'Cookie': `apiKey=JlE5Jldo5Jibnk5O5hTx6XVqsJu4WJ26${authCookie ? `; ${authCookie}` : ''}`
          }
        })

        currentUser = response.data

        // 验证成功后更新凭据
        if (session.userId && currentUser) {
          await saveAuth(session.userId, {
            currentUser,
            authCookie,
            authToken,
          })
        }

        return `验证成功！欢迎 ${currentUser.displayName}`
      } catch (error) {
        ctx.logger('vrchat-api').error('验证码验证失败:', error)
        if (error.response?.status === 401) {
          return '验证失败：认证已过期，请重新登录'
        }
        return '验证失败，请检查验证码是否正确'
      }
    })

  // 获取用户信息命令
  ctx.command('vrchat.me', '获取当前VRChat用户信息')
    .action(async ({ session }) => {
      if (!currentUser) {
        return '未登录，请先使用 vrchat.login 命令登录'
      }

      return [
        `用户名: ${currentUser.displayName}`,
        `状态: ${currentUser.status}`,
        `好友数: ${currentUser.friends?.length || 0}`,
        `在线状态: ${currentUser.state}`,
        `最后登录: ${new Date(currentUser.last_login).toLocaleString()}`
      ].join('\n')
    })

  // 获取Avatar信息命令
  ctx.command('vrchat.avatar <avatarId>', '获取指定Avatar的信息')
    .action(async ({ session }, avatarId) => {
      if (!currentUser) {
        return '未登录，请先使用 vrchat.login 命令登录'
      }

      if (!avatarId) {
        return '请提供Avatar ID'
      }

      try {
        // 使用auth cookie进行认证
        const headers = {
          'User-Agent': ctx.config.userAgent,
          'Cookie': `apiKey=JlE5Jldo5Jibnk5O5hTx6XVqsJu4WJ26${authCookie ? `; ${authCookie}` : ''}`
        }

        const response = await axios.get(`${BASE_URL}/avatars/${avatarId}`, {
          headers
        })

        const avatar = response.data

        // 格式化返回信息
        return [
          `Avatar名称: ${avatar.name}`,
          `作者: ${avatar.authorName}`,
          `描述: ${avatar.description || '无描述'}`,
          `发布状态: ${avatar.releaseStatus}`,
          `版本: ${avatar.version}`,
          `支持的平台: ${avatar.supportedPlatforms?.join(', ') || '未知'}`,
          `标签: ${avatar.tags?.join(', ') || '无标签'}`,
          `创建时间: ${new Date(avatar.created_at).toLocaleString()}`,
          `更新时间: ${new Date(avatar.updated_at).toLocaleString()}`,
          avatar.thumbnailImageUrl ? segment.image(avatar.thumbnailImageUrl) : ''
        ].filter(Boolean).join('\n')

      } catch (error) {
        ctx.logger('vrchat-api').error('获取Avatar信息失败:', error)

        if (error.response) {
          switch (error.response.status) {
            case 401:
              return '获取失败：认证已过期，请重新登录'
            case 403:
              return '获取失败：权限不足'
            case 404:
              return '未找到指定的Avatar'
            default:
              return '获取失败，请稍后重试'
          }
        }

        return '获取失败，请检查网络连接'
      }
    })

  // 简化获取世界信息的函数
  async function getWorldInfo(worldId: string, headers: any) {
    try {
      if (!worldId || worldId === 'private' || worldId === 'offline') {
        return null
      }
      const response = await axios.get(`${BASE_URL}/worlds/${worldId}`, { headers })
      return {
        id: worldId,
        name: response.data.name
      }
    } catch (error) {
      ctx.logger('vrchat-api').warn(`获取世界名称失败 (${worldId}):`, error)
      return null
    }
  }

  // 获取好友列表命令
  ctx.command('vrchat.friends', '获取好友列表')
    .option('offline', '-o  显示离线好友')
    .action(async ({ options }) => {
      if (!currentUser) {
        return '未登录，请先使用 vrchat.login 命令登录'
      }

      try {
        const headers = {
          'User-Agent': ctx.config.userAgent,
          'Cookie': `apiKey=JlE5Jldo5Jibnk5O5hTx6XVqsJu4WJ26${authCookie ? `; ${authCookie}` : ''}`
        }

        const response = await axios.get(`${BASE_URL}/auth/user/friends`, {
          headers,
          params: {
            offline: options.offline || false
          }
        })

        const friends = response.data

        if (!friends.length) {
          return '暂无在线好友'
        }

        // 获取所有世界信息
        const worldPromises = friends.map(friend => {
          if (friend.location && friend.location !== 'private' && friend.location !== 'offline') {
            const worldId = friend.location.split(':')[0]
            return getWorldInfo(worldId, headers)
          }
          return Promise.resolve(null)
        })

        // 等待所有世界信息请求完成
        const worlds = await Promise.all(worldPromises)

        // 创建世界ID到名称的映射
        const worldCache = new Map()
        worlds.forEach(world => {
          if (world) {
            worldCache.set(world.id, world.name)
          }
        })

        // 格式化好友信息
        const friendList = friends.map(friend => {
          const status = friend.status || '未知'
          let location = '未知位置'

          if (friend.location === 'private') {
            location = '私密世界'
          } else if (friend.location === 'offline') {
            location = '离线'
          } else if (friend.location) {
            const worldId = friend.location.split(':')[0]
            const instanceId = friend.location.split(':')[1] || ''
            const worldName = worldCache.get(worldId)

            // 添加调试日志
            ctx.logger('vrchat-api').debug(`World ID: ${worldId}, Name: ${worldName}, Cache:`, worldCache)

            location = worldName
              ? `${worldName}${instanceId ? ` (${instanceId})` : ''}`
              : `${worldId}${instanceId ? `:${instanceId}` : ''}`
          }

          const statusEmoji = {
            'active': '🟢',
            'join me': '🔵',
            'ask me': '🟡',
            'busy': '🔴',
            'offline': '⚫'
          }[friend.status?.toLowerCase()] || '⚪'

          return [
            `${statusEmoji} ${friend.displayName}`,
            `状态: ${status}`,
            `位置: ${location}`,
            friend.statusDescription ? `状态描述: ${friend.statusDescription}` : null,
            friend.last_login ? `最后登录: ${new Date(friend.last_login).toLocaleString()}` : null,
            ''  // 添加空行分隔
          ].filter(Boolean).join('\n')
        })

        // 添加统计信息
        const onlineFriends = friends.filter(f => f.status?.toLowerCase() !== 'offline')
        const stats = [
          '===== 好友统计 =====',
          `在线好友: ${onlineFriends.length}`,
          `总好友数: ${friends.length}`,
          ''
        ].join('\n')

        return stats + friendList.join('\n')

      } catch (error) {
        ctx.logger('vrchat-api').error('获取好友列表失败:', error)

        if (error.response) {
          switch (error.response.status) {
            case 401:
              return '获取失败：认证已过期，请重新登录'
            case 403:
              return '获取失败：权限不足'
            default:
              return '获取失败，请稍后重试'
          }
        }

        return '获取失败，请检查网络连接'
      }
    })

  ctx.command('vrchat.userSearch <username>', '搜索用户')
    .option('limit', '-l <number> 显示结果数量', { fallback: 5 })
    .action(async ({ session, options }, username) => {
      if (!currentUser) {
        return '未登录，请先使用 vrchat.login 命令登录'
      }
      if (!username) {
        return '请提供玩家名'
      }
      try {
        const response = await axios.get(`${BASE_URL}/users`, {
          headers: {
            'User-Agent': ctx.config.userAgent,
            'Cookie': `apiKey=JlE5Jldo5Jibnk5O5hTx6XVqsJu4WJ26${authCookie ? `; ${authCookie}` : ''}`
          },
          params: {
            search: username,
            n: options.limit
          }
        })

        const users = response.data
        if (!users.length) {
          return '未找到用户'
        }

        // 只处理指定数量的用户
        const limitedUsers = users.slice(0, options.limit)

        // 为每个用户创建详细信息
        const userInfos = limitedUsers.map((user, index) => {
          return [
            `=== 用户 #${index + 1} ===`,
            `用户名: ${user.displayName}`,
            `ID: ${user.id}`,
            `状态: ${user.status || '未知'}`,
            `位置: ${user.location || '未知'}`,
            `最后登录: ${new Date(user.last_login).toLocaleString()}`,
            `好友数: ${user.friends?.length || 0}`,
            `在线状态: ${user.state || '未知'}`,
            user.bio ? `个人简介: ${user.bio}` : null,
            user.pronouns ? `代词: ${user.pronouns}` : null,
            user.currentAvatarImageUrl ? segment.image(user.currentAvatarImageUrl) : null,
            '' // 添加空行分隔
          ].filter(Boolean).join('\n')
        })

        // 添加搜索统计信息
        const header = [
          `===== 搜索结果 =====`,
          `关键词: ${username}`,
          `找到 ${users.length} 个用户，显示前 ${userInfos.length} 个`,
          ''
        ].join('\n')

        return header + userInfos.join('\n')

      } catch (error) {
        ctx.logger('vrchat-api').error('搜索用户失败:', error)
        if (error.response) {
          switch (error.response.status) {
            case 401:
              return '搜索失败：认证已过期，请重新登录'
            case 403:
              return '搜索失败：权限不足'
            default:
              return '搜索失败，请稍后重试'
          }
        }
        return '搜索失败，请检查网络连接'
      }
    })

  ctx.command('vrchat.searchworld <worldname>', '搜索VRChat世界')
    .option('limit', '-l <number> 显示结果数量', { fallback: 5 }) // 默认显示5个结果
    .action(async ({ session, options }, worldname) => {
      if (!currentUser) {
        return '未登录，请先使用 vrchat.login 命令登录'
      }
      if (!worldname) {
        return '请提供世界名称'
      }
      try {
        const response = await axios.get(`${BASE_URL}/worlds`, {
          headers: {
            'User-Agent': ctx.config.userAgent,
            'Cookie': `apiKey=JlE5Jldo5Jibnk5O5hTx6XVqsJu4WJ26${authCookie ? `; ${authCookie}` : ''}`
          },
          params: {

            search: worldname,
            n: options.limit // 限制返回数量
          }
        })

        const worlds = response.data
        if (!worlds.length) {
          return '未找到世界'
        }

        // 只处理指定数量的世界
        const limitedWorlds = worlds.slice(0, options.limit)

        // 为每个世界创建详细信息
        const worldInfos = limitedWorlds.map((world, index) => {
          return [
            `=== 世界 #${index + 1} ===`,
            `世界名称: ${world.name}`,
            `世界ID: ${world.id}`,
            `作者: ${world.authorName}`,
            `描述: ${world.description || '无描述'}`,
            `容量: ${world.capacity}人 (推荐${world.recommendedCapacity}人)`,
            `当前人数: ${world.occupants}人`,
            `收藏数: ${world.favorites}`,
            `访问量: ${world.visits}`,
            `热度: ${world.heat}`,
            `发布状态: ${world.releaseStatus}`,
            `标签: ${world.tags?.join(', ') || '无标签'}`,
            `创建时间: ${new Date(world.created_at).toLocaleString()}`,
            `更新时间: ${new Date(world.updated_at).toLocaleString()}`,
            `Unity版本: ${world.unityPackages?.[0]?.unityVersion || '未知'}`,
            world.thumbnailImageUrl ? segment.image(world.thumbnailImageUrl) : null,
            '' // 添加空行分隔
          ].filter(Boolean).join('\n')
        })

        // 添加搜索统计信息
        const header = [
          `===== 搜索结果 =====`,
          `关键词: ${worldname}`,
          `找到 ${worlds.length} 个世界，显示前 ${worldInfos.length} 个`,
          ''
        ].join('\n')

        return header + worldInfos.join('\n')

      } catch (error) {
        ctx.logger('vrchat-api').error('搜索世界失败:', error)
        if (error.response) {
          switch (error.response.status) {
            case 401:
              return '搜索失败：认证已过期，请重新登录'
            case 403:
              return '搜索失败：权限不足'
            default:
              return '搜索失败，请稍后重试'
          }
        }
        return '搜索失败，请检查网络连接'
      }
    })


  // API调用频率限制
  ctx.middleware(async (session, next) => {
    if (session.content.startsWith('vrchat.')) {
      await new Promise(resolve => setTimeout(resolve, 1000))
    }
    return next()
  })
}
