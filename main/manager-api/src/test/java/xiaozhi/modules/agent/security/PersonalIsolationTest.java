package xiaozhi.modules.agent.security;

import java.util.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import xiaozhi.common.exception.*;
import xiaozhi.common.redis.*;
import xiaozhi.common.utils.MessageUtils;
import xiaozhi.modules.agent.controller.*;
import xiaozhi.modules.agent.dao.AgentDao;
import xiaozhi.modules.agent.dto.*;
import xiaozhi.modules.agent.entity.*;
import xiaozhi.modules.agent.service.*;
import xiaozhi.modules.agent.service.impl.AgentServiceImpl;
import xiaozhi.modules.agent.vo.AgentInfoVO;
import xiaozhi.modules.config.service.impl.ConfigServiceImpl;
import xiaozhi.modules.device.dao.DeviceDao;
import xiaozhi.modules.device.dto.DeviceManualAddDTO;
import xiaozhi.modules.device.entity.DeviceEntity;
import xiaozhi.modules.device.service.DeviceService;
import xiaozhi.modules.device.service.impl.DeviceServiceImpl;
import xiaozhi.modules.security.config.ShiroConfig;
import xiaozhi.modules.security.entity.SysUserTokenEntity;
import xiaozhi.modules.security.oauth2.*;
import xiaozhi.modules.security.password.PasswordUtils;
import xiaozhi.modules.security.service.ShiroService;
import xiaozhi.modules.sys.dao.SysUserDao;
import xiaozhi.modules.sys.dto.SysUserDTO;
import xiaozhi.modules.sys.entity.SysUserEntity;
import xiaozhi.modules.sys.service.SysParamsService;
import xiaozhi.modules.sys.service.impl.SysUserServiceImpl;

/** No SQL server/services: native authentication/guards/controllers are REAL;
 * DAO/Redis fixtures supply synthetic state only, not proof of SQL isolation.
 */
class PersonalIsolationTest {
    AgentDao agentDao;
    AgentServiceImpl agents;
    DeviceDao deviceDao;
    DeviceServiceImpl devices;
    RedisUtils redis;
    Map<String, SysUserTokenEntity> tokens;
    Map<Long, SysUserEntity> users;
    Map<String, Object> cache;
    DefaultWebSecurityManager security;
    AgentInfoVO a, b;

    @BeforeEach void setUp() {
        StaticMessageSource messages = new StaticMessageSource();
        messages.setUseCodeAsDefaultMessage(true);
        ReflectionTestUtils.setField(MessageUtils.class, "messageSource", messages);
        agentDao = mock(AgentDao.class);
        deviceDao = mock(DeviceDao.class);
        redis = mock(RedisUtils.class);
        cache = new HashMap<>();
        when(redis.get(anyString())).thenAnswer(i -> cache.get(i.getArgument(0)));
        a = agent("agent-a", 11L); b = agent("agent-b", 22L);
        when(agentDao.selectById("agent-a")).thenReturn(a);
        when(agentDao.selectById("agent-b")).thenReturn(b);
        agents = new AgentServiceImpl(agentDao, null, null, null, redis, null,
            null, null, null, null, null, null, null, null);
        devices = new DeviceServiceImpl(deviceDao, agentDao, null, null, redis, null, null);
        ReflectionTestUtils.setField(devices, "baseDao", deviceDao);
        users = new HashMap<>(); tokens = new HashMap<>();
        for (long id : new long[]{11, 22, 1}) {
            SysUserEntity user = new SysUserEntity();
            user.setId(id); user.setUsername("synthetic-" + id);
            user.setStatus(1); user.setSuperAdmin(id == 1 ? 1 : 0); users.put(id, user);
            SysUserTokenEntity token = new SysUserTokenEntity();
            token.setUserId(id); token.setToken("fixture-" + id);
            token.setExpireDate(new Date(System.currentTimeMillis() + 60000)); tokens.put(token.getToken(), token);
        }
        Oauth2Realm realm = new Oauth2Realm();
        ReflectionTestUtils.setField(realm, "shiroService", new ShiroService() {
            public SysUserTokenEntity getByToken(String token) { return tokens.get(token); }
            public SysUserEntity getUser(Long id) { return users.get(id); }
        });
        security = new DefaultWebSecurityManager(realm);
        security.setRememberMeManager(null);
        ThreadContext.bind(security);
    }

    @AfterEach void clean() {
        ThreadContext.remove(); security.destroy();
        ReflectionTestUtils.setField(MessageUtils.class, "messageSource", null);
    }

    AgentInfoVO agent(String id, Long owner) {
        AgentInfoVO agent = new AgentInfoVO(); agent.setId(id); agent.setUserId(owner); return agent;
    }
    DeviceEntity device(String id, String agent, Long owner) {
        DeviceEntity d = new DeviceEntity(); d.setId(id); d.setAgentId(agent); d.setUserId(owner); return d;
    }
    void login(long id) {
        ThreadContext.unbindSubject();
        Subject subject = new Subject.Builder(security).buildSubject();
        subject.login(new Oauth2Token("fixture-" + id)); ThreadContext.bind(subject);
    }

    @Test void realNativeRealmAuthenticatesIndependentUsersAndRejectsExpiredRevokedAndDisabled() {
        login(11); assertTrue(agents.checkAgentPermission("agent-a", 11L));
        assertFalse(agents.checkAgentPermission("agent-b", 11L));
        login(22); assertTrue(agents.checkAgentPermission("agent-b", 22L));
        assertFalse(agents.checkAgentPermission("agent-a", 22L));
        login(1); assertFalse(agents.checkAgentPermission("agent-a", 1L));
        tokens.get("fixture-11").setExpireDate(new Date(0));
        assertThrows(org.apache.shiro.authc.AuthenticationException.class, () -> login(11));
        tokens.remove("fixture-22");
        assertThrows(org.apache.shiro.authc.AuthenticationException.class, () -> login(22));
        users.get(1L).setStatus(0);
        assertThrows(org.apache.shiro.authc.AuthenticationException.class, () -> login(1));
    }

    @Test void foreignActivationAndManualBindingStopBeforeReadingTicketsOrWriting() {
        login(11);
        assertThrows(RenException.class, () -> devices.deviceActivation("agent-b", "123456"));
        DeviceManualAddDTO dto = new DeviceManualAddDTO(); dto.setAgentId("agent-b");
        dto.setMacAddress("synthetic-device-a");
        assertThrows(RenException.class, () -> devices.manualAddDevice(11L, dto));
        assertThrows(RenException.class, () -> devices.manualAddDevice(22L, dto));
        verifyNoInteractions(redis, deviceDao);
        dto.setAgentId("agent-a"); devices.manualAddDevice(11L, dto);
        verify(deviceDao).insert(argThat((DeviceEntity d) -> d.getUserId().equals(11L) && d.getAgentId().equals("agent-a")));
    }

    @Test void legacyBindingCannotReturnConfigAndAuthorizedDevicesShareStableIdentity() {
        DeviceService lookup = mock(DeviceService.class);
        AgentService reader = mock(AgentService.class);
        SysUserDao owners = mock(SysUserDao.class);
        when(owners.selectById(11L)).thenReturn(users.get(11L));
        when(reader.getAgentById("agent-a")).thenReturn(a);
        when(reader.getAgentById("agent-b")).thenReturn(b);
        when(lookup.getDeviceByMacAddress("bad")).thenReturn(device("bad", "agent-b", 11L));
        when(lookup.getDeviceByMacAddress("a1")).thenReturn(device("a1", "agent-a", 11L));
        when(lookup.getDeviceByMacAddress("a2")).thenReturn(device("a2", "agent-a", 11L));
        var models = mock(xiaozhi.modules.model.service.ModelConfigService.class);
        var timbres = mock(xiaozhi.modules.timbre.service.TimbreService.class);
        var sharedTts = new xiaozhi.modules.model.entity.ModelConfigEntity();
        sharedTts.setId("TTS_shared");
        sharedTts.setConfigJson(new cn.hutool.json.JSONObject(Map.of("type", "edge", "voice", "default")));
        when(models.getModelByIdFromCache("TTS_shared")).thenReturn(sharedTts);
        var voice = new xiaozhi.modules.timbre.vo.TimbreDetailsVO(); voice.setTtsVoice("private-a-voice");
        when(timbres.get("voice-a")).thenReturn(voice);
        a.setTtsModelId("TTS_shared"); a.setTtsVoiceId("voice-a");
        ConfigServiceImpl configs = new ConfigServiceImpl(mock(SysParamsService.class), lookup, owners,
            models, reader, null, redis,
            timbres, mock(AgentPluginMappingService.class),
            mock(AgentMcpAccessPointService.class), mock(AgentContextProviderService.class),
            mock(xiaozhi.modules.voiceclone.service.VoiceCloneService.class),
            mock(xiaozhi.modules.agent.dao.AgentVoicePrintDao.class), null);
        assertThrows(RenException.class, () -> configs.getAgentModels("bad", Map.of()));
        var first = configs.getAgentModels("a1", Map.of());
        var second = configs.getAgentModels("a2", Map.of());
        assertEquals(Map.of("ownerId", "11", "agentId", "agent-a"), first.get("identity"));
        assertEquals(first.get("identity"), second.get("identity"));
        assertEquals("default", sharedTts.getConfigJson().get("voice"), "Personal voice must not mutate shared provider config");
        assertEquals(false, first.get("personal_tools_allowed"));
        assertEquals(Map.of(), first.get("plugins")); assertEquals("", first.get("mcp_endpoint"));
    }

    @Test void authenticatedAudioCannotBeRedeemedByAnotherAccountEvenWithValidUuid() throws Exception {
        AgentChatHistoryService history = mock(AgentChatHistoryService.class);
        AgentChatAudioService audio = mock(AgentChatAudioService.class);
        when(history.getAgentIdByAudioId("audio-a")).thenReturn("agent-a");
        when(audio.getAudio("audio-a")).thenReturn(new byte[]{1,2,3});
        cache.put(RedisKeys.getAgentAudioIdKey("valid-ticket"), "audio-a");
        AgentController controller = new AgentController(agents, history, audio, null, redis, null);
        var factory = ShiroConfig.shirFilter(security, mock(SysParamsService.class));
        var filter = (jakarta.servlet.Filter) factory.getObject();
        MockMvc mvc = MockMvcBuilders.standaloneSetup(controller)
            .setControllerAdvice(new RenExceptionHandler()).addFilters(filter).build();
        mvc.perform(get("/agent/play/valid-ticket")).andExpect(jsonPath("$.code").value(ErrorCode.UNAUTHORIZED));
        mvc.perform(get("/agent/play/valid-ticket").header("Authorization", "Bearer fixture-22"))
            .andExpect(jsonPath("$.code").value(ErrorCode.NO_PERMISSION));
        verifyNoInteractions(audio);
        mvc.perform(get("/agent/play/valid-ticket").header("Authorization", "Bearer fixture-11"))
            .andExpect(content().bytes(new byte[]{1,2,3}));
        verify(redis).delete(RedisKeys.getAgentAudioIdKey("valid-ticket"));
    }

    @Test void foreignHistoryTicketIsRejectedBeforeReadAndNotConsumed() {
        var history = mock(AgentChatHistoryService.class);
        var controller = new AgentChatHistoryController(null, history, agents, redis);
        cache.put(RedisKeys.getChatHistoryKey("ticket"), "agent-a:session-a");
        login(22);
        assertThrows(RenException.class, () -> controller.downloadCurrentSession("ticket", null));
        assertThrows(RenException.class, () -> controller.downloadCurrentSessionWithPrevious("ticket", null));
        verifyNoInteractions(history); verify(redis, never()).delete(anyString());
        login(1);
        assertThrows(RenException.class, () -> controller.downloadCurrentSession("ticket", null));
    }

    @Test void commonProvisionUsesRealHashAndNeverPromotesOnEmptyDatabaseOrInjectedRole() {
        SysUserDao dao = mock(SysUserDao.class);
        when(dao.selectCount(any())).thenReturn(0L);
        var service = new SysUserServiceImpl(dao, null, null, null);
        ReflectionTestUtils.setField(service, "baseDao", dao);
        SysUserDTO dto = new SysUserDTO(); dto.setUsername("synthetic-common");
        dto.setPassword("Synthetic-Only-95!"); dto.setSuperAdmin(1);
        service.saveCommon(dto);
        verify(dao).insert(argThat((SysUserEntity u) -> u.getSuperAdmin() == 0 && u.getStatus() == 1
            && !u.getPassword().equals(dto.getPassword()) && PasswordUtils.matches(dto.getPassword(), u.getPassword())));
    }

    @Test void voiceResourcesRejectForeignUserIdsIncludingMasterProductRequest() {
        var voices = mock(xiaozhi.modules.voiceclone.service.VoiceCloneService.class);
        var controller = new xiaozhi.modules.voiceclone.controller.VoiceResourceController(voices, null);
        login(11);
        assertThrows(RenException.class, () -> controller.getByUserId(22L));
        verifyNoInteractions(voices);
        controller.getByUserId(11L); verify(voices).getByUserIdWithNames(11L);
        login(1); assertThrows(RenException.class, () -> controller.getByUserId(11L));
    }

    @Test void foreignNameAndConfigChangesAreRejectedBeforeSnapshotOrWrite() {
        when(agentDao.selectByIdForUpdate("agent-b")).thenReturn(b);
        login(11);
        AgentUpdateDTO dto = new AgentUpdateDTO(); dto.setAgentName("Tentativa alheia");
        assertThrows(RenException.class, () -> agents.updateAgentById("agent-b", dto, 11L));
        verify(agentDao, never()).updateById(any(AgentEntity.class));
        dto.setFunctions(List.of());
        assertThrows(RenException.class, () -> agents.updateAgentById("agent-a", dto, 11L));
        login(1);
        dto.setFunctions(null);
        assertThrows(RenException.class, () -> agents.updateAgentById("agent-b", dto, 1L));
    }

    @Test void realHttpHistoryRoutesRejectForeignAgentAndScopeOwnSessionQuery() throws Exception {
        var history = mock(AgentChatHistoryService.class);
        var controller = new AgentController(agents, history, null, null, redis, null);
        var filter = (jakarta.servlet.Filter) ShiroConfig.shirFilter(security, mock(SysParamsService.class)).getObject();
        var mvc = MockMvcBuilders.standaloneSetup(controller).setControllerAdvice(new RenExceptionHandler())
            .addFilters(filter).build();
        mvc.perform(get("/agent/agent-b/sessions").header("Authorization", "Bearer fixture-11"))
            .andExpect(jsonPath("$.code").value(ErrorCode.NO_PERMISSION));
        verifyNoInteractions(history);
        mvc.perform(get("/agent/agent-a/chat-history/session-b").header("Authorization", "Bearer fixture-11"))
            .andExpect(jsonPath("$.code").value(0));
        verify(history).getChatHistoryBySessionId("agent-a", "session-b");
        // Real service SQL predicate is covered by the existing fork history implementation;
        // this test proves client sessionId does not change the authorized agent argument.
    }

    @Test void ownNameUpdateUsesNativePersistenceAndPersonalDtoDoesNotReturnConnectorSecrets() {
        var contexts = mock(AgentContextProviderService.class);
        var files = mock(xiaozhi.modules.correctword.service.CorrectWordFileService.class);
        var snapshots = mock(AgentSnapshotService.class);
        var service = new AgentServiceImpl(agentDao, null, null, null, redis, null,
            null, null, null, null, contexts, null, files, snapshots);
        ReflectionTestUtils.setField(service, "baseDao", agentDao);
        var binding = new AgentPluginMapping(); binding.setParamInfo("{\"api_key\":\"synthetic-private\"}");
        a.setFunctions(List.of(binding));
        when(agentDao.selectAgentInfoById("agent-a")).thenReturn(a);
        when(agentDao.selectByIdForUpdate("agent-a")).thenReturn(a);
        login(11);
        assertTrue(service.getAgentById("agent-a", 11L).getFunctions().isEmpty());
        AgentUpdateDTO update = new AgentUpdateDTO(); update.setAgentName("Agente de A");
        service.updateAgentById("agent-a", update, false);
        verify(agentDao).updateById(argThat((AgentEntity entity) -> entity.getUserId().equals(11L)
            && entity.getId().equals("agent-a") && entity.getAgentName().equals("Agente de A")));
        assertEquals("Agente de A", service.getAgentById("agent-a", 11L).getAgentName());
        login(22);
        assertThrows(RenException.class, () -> service.getAgentById("agent-a", 22L));
    }
}
